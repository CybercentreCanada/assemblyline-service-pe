import copy
import csv
import datetime
import hashlib
import json
import os
import pathlib
import re
import struct
import subprocess
import tempfile
import warnings
from collections import defaultdict
from io import BytesIO

import lief
import ordlookup
from assemblyline.common import forge
from assemblyline.common.entropy import calculate_partition_entropy
from assemblyline.odm.models.ontology.filetypes import PE as PE_ODM
from assemblyline_toolbox import SsdeepHasher
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    GraphSectionBody,
    Heuristic,
    ImageSectionBody,
    OrderedKVSectionBody,
    Result,
    ResultMultiSection,
    ResultOrderedKeyValueSection,
    ResultSection,
    ResultTableSection,
    TableRow,
    TableSectionBody,
    TextSectionBody,
)
from assemblyline_v4_service.common.task import PARENT_RELATION
from PIL import Image

from . import unmapper
from .code_pages import CODE_PAGES
from .sublangs import sublang_name, sublang_pair_name

# Disable logging from LIEF
lief.logging.disable()

MZ = [ord(x) for x in "MZ"]
DOS_MODE = [ord(x) for x in "This program cannot be run in DOS mode"]
ACCEPTED_ALGORITHMS = [
    "RSA",
    "SHA1_RSA",
    "SHA_256_RSA",
    "SHA_384_RSA",
    "SHA_512_RSA",
    "DSA",  # Doesn't exist
    "SHA1_DSA",
    "SHA1_ECDSA",
    "SHA_224_ECDSA",  # Doesn't exist
    "SHA_256_ECDSA",
    "SHA_384_ECDSA",
    "SHA_512_ECDSA",
]
cert_verification_entries = {entry.value: entry for entry in lief.PE.x509.VERIFICATION_FLAGS}

accelerator_flags_entries = {entry.value: entry for entry in lief.PE.ResourceAccelerator.FLAGS}

PACKED_SECTION_NAMES = ["UPX", "UPX0", "UPX1", "ASPack", "vmp0", "themida"]
PACKED_SECTION_NAMES += [f".{x}" for x in PACKED_SECTION_NAMES]
MALICIOUS_SECTION_NAMES = [(".bak", None), (".lol", None), (".rsrc", 3221487648)]
NON_STANDARD_SECTION_NAMES = ["_rdata", ".rr", ".didat"]


def search_list_in_list(what, into):
    try:
        while True:
            index = into.index(what[0])
            into = into[index:]
            if what == into[: len(what)]:
                return True
            into = into[1:]
    except ValueError:
        return False


def from_msdos(msdos_t):
    # Taken from https://0xc0decafe.com/malware-analyst-guide-to-pe-timestamps/ which was
    # taken from https://github.com/digitalsleuth/time_decode
    msdos = hex(msdos_t)[2:]
    binary = "{0:032b}".format(int(msdos, 16))
    stamp = [binary[:7], binary[7:11], binary[11:16], binary[16:21], binary[21:27], binary[27:32]]
    for val in stamp[:]:
        dec = int(val, 2)
        stamp.remove(val)
        stamp.append(dec)

    dos_year = stamp[0] + 1980
    dos_month = stamp[1]
    dos_day = stamp[2]
    dos_hour = stamp[3]
    dos_min = stamp[4]
    dos_sec = stamp[5] * 2
    if (
        dos_year in range(1970, 2100)
        and dos_month in range(1, 13)
        and dos_day in range(1, 32)
        and dos_hour in range(0, 24)
        and dos_min in range(0, 60)
        and dos_sec in range(0, 60)
    ):
        try:
            return int(datetime.datetime(dos_year, dos_month, dos_day, dos_hour, dos_min, dos_sec).timestamp())
        except ValueError:
            pass
    return msdos_t  # Not a valid MS DOS timestamp


def get_powers(x):
    if x == 0:
        return [0]
    powers = []
    i = 1
    while i <= x:
        if i & x:
            powers.append(i)
        i <<= 1
    return powers


def bytes_to_backslashreplace_utf8_str(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "backslashreplace")
    return value


def extract_cert_info(cert, trusted_certs):
    cert_struct = {
        "version": cert.version,
        "subject": bytes_to_backslashreplace_utf8_str(cert.subject),
        "issuer": bytes_to_backslashreplace_utf8_str(cert.issuer),
        "serial_number": cert.serial_number.hex(),
        "key_type": cert.key_type.name,
        "key_usage": [usage.name for usage in cert.key_usage],
        "certificate_policies": cert.certificate_policies,
        "ext_key_usage": cert.ext_key_usage,
        "valid_from": cert.valid_from,
        "valid_to": cert.valid_to,
        "signature": cert.signature.hex(),
        "signature_algorithm": cert.signature_algorithm,
        "is_trusted": " | ".join(
            [cert_verification_entries[x].name for x in get_powers(cert.is_trusted_by(trusted_certs).__int__())]
        ),
        "raw_hex": cert.raw.hex(),
    }
    if cert.rsa_info is not None:
        cert_struct["rsa_info"] = {
            "d_param": cert.rsa_info.D.hex(),
            "e_param": cert.rsa_info.E.hex(),
            "n_param": cert.rsa_info.N.hex(),
            "p_param": cert.rsa_info.P.hex(),
            "q_param": cert.rsa_info.Q.hex(),
        }
        cert_struct["key_size"] = cert.rsa_info.key_size
    return cert_struct


def calc_imphash_sha1(imports):
    sorted_import_list = []
    for lib_name, entries in imports.items():
        for entry in entries:
            if entry["name"] == "":
                import_name = ordlookup.ordLookup(str.encode(lib_name), entry["ordinal"], make_name=False)
                sorted_import_list.append(str(entry["ordinal"]) if import_name is None else import_name.decode())
            else:
                sorted_import_list.append(entry["name"])

    sorted_import_list.sort()
    sorted_import_list = [str.encode(x) for x in sorted_import_list]
    return hashlib.sha1(b" ".join(sorted_import_list)).hexdigest()


def calc_impfuzzy(imports, sort=False):
    impstrs = []
    exts = ["ocx", "sys", "dll"]
    for lib_name, entries in imports.items():
        modified_lib_name = lib_name.lower()
        parts = modified_lib_name.rsplit(".", 1)
        if len(parts) > 1 and parts[1] in exts:
            modified_lib_name = parts[0]

        for entry in entries:
            if entry["name"] == "":
                import_name = ordlookup.ordLookup(str.encode(lib_name), entry["ordinal"], make_name=True)
                impstrs.append(f"{modified_lib_name}.{import_name.decode().lower()}")
            else:
                impstrs.append(f"{modified_lib_name}.{entry['name'].lower()}")

    if sort:
        impstrs.sort()

    apilist = ",".join(impstrs)
    return SsdeepHasher.hash(apilist)


def generate_checksum(filename, checksum_offset):
    # Code taken from https://github.com/erocarrera/pefile/blob/master/pefile.py#L7131 until
    # LIEF includes a way to compute it internally :
    #   https://github.com/lief-project/LIEF/issues/660
    # The checksum_offset can be found with
    # checksum_offset = pe_lief.dos_header.addressof_new_exeheader + 0x58

    with open(filename, "rb") as f:
        data = bytearray(f.read())

    checksum = 0
    remainder = len(data) % 4
    data_len = len(data) + ((4 - remainder) * (remainder != 0))

    for i in range(int(data_len / 4)):
        if i == int(checksum_offset / 4):
            continue
        if i + 1 == (int(data_len / 4)) and remainder:
            dword = struct.unpack("I", data[i * 4 :] + (b"\0" * (4 - remainder)))[0]
        else:
            dword = struct.unpack("I", data[i * 4 : i * 4 + 4])[0]
        checksum += dword
        if checksum >= 2**32:
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)

    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = (checksum) + (checksum >> 16)
    checksum = checksum & 0xFFFF

    return checksum + len(data)


# handle PE machine type parsing in all cases - parse hex of type if it isn't identified by LIEF machinetype enum
# https://github.com/lief-project/LIEF/issues/1170
def parse_machine_type(header):
    try:
        return header.machine.name
    except AttributeError:
        return hex(header.machine)


def get_lief_enum_name(enum):
    try:
        return enum.name
    except (AttributeError, ValueError):
        return enum


class TreeIcon:
    """Icon rebuilt from a raw RT_ICON resource tree leaf.

    LIEF's ResourcesManager.icons() only yields icons that are referenced from a parsable
    RT_GROUP_ICON entry. On some corrupted/packed samples, LIEF 1.0.0 fails to keep the
    GROUP_ICON data node (that LIEF 0.16.4 kept) and the manager then yields no icon at all,
    even though the RT_ICON leaves and their pixel data are intact. This mimics the subset of
    lief.PE.ResourceIcon that add_resources() uses, from a leaf's content alone.
    """

    def __init__(self, icon_id, lang_id, pixels):
        self.id = icon_id
        # Split the full 16-bit language identifier the way lief.PE.ResourceIcon does
        self.lang = lang_id & 0x3FF
        self.sublang = (lang_id >> 10) & 0x3F
        self.pixels = pixels
        self.width = 0
        self.height = 0
        self.planes = 0
        self.bit_count = 0
        if pixels[:8] == b"\x89PNG\r\n\x1a\x0a":
            # Vista+ icons can be PNG-compressed: dimensions are in the IHDR chunk
            self.width, self.height = struct.unpack(">II", pixels[16:24])
            self.planes = 1
            self.bit_count = 32
        elif len(pixels) >= 16:
            # Otherwise the data starts with a BITMAPINFOHEADER, where the height covers
            # both the XOR and AND masks (hence half of it is the real icon height)
            _, self.width, height, self.planes, self.bit_count = struct.unpack("<IiiHH", pixels[:16])
            self.height = abs(height) // 2

    def save(self, path):
        color_count = 2**self.bit_count if 0 < self.bit_count < 8 else 0
        with open(path, "wb") as f:
            f.write(struct.pack("<HHH", 0, 1, 1))
            f.write(
                struct.pack(
                    "<BBBBHHII",
                    self.width & 0xFF,
                    self.height & 0xFF,
                    color_count,
                    0,
                    self.planes,
                    self.bit_count,
                    len(self.pixels),
                    22,
                )
            )
            f.write(self.pixels)


def group_icon_data_missing(binary):
    """Detect RT_GROUP_ICON directories that exist without any data leaf.

    This is the signature of LIEF 1.0.0's parser dropping the group data node on some
    corrupted samples (that 0.16.4 kept). When the data leaves are present, the manager
    had a legitimate, content-based reason to reject them (e.g. bad GRPICONDIR type),
    and LIEF 0.16.4 would not have yielded icons either.

    Returns:
        bool: True when at least one RT_GROUP_ICON directory exists and none of them
        contains a data leaf, meaning the icons should be rebuilt from the RT_ICON tree.
        False when there is no RT_GROUP_ICON directory, or when at least one group data
        leaf is present (the manager's empty result is then content-based and final).
    """
    found_group_dir = False
    for top in binary.resources.childs:
        if top.id != lief.PE.ResourcesManager.TYPE.GROUP_ICON.value:
            continue
        for group_dir in top.childs:
            found_group_dir = True
            for leaf in group_dir.childs:
                if leaf.is_data:
                    return False
    return found_group_dir


def icons_from_resource_tree(binary):
    """Rebuild the icons directly from the RT_ICON resource tree leaves.

    Returns:
        list[TreeIcon]: one TreeIcon per non-empty RT_ICON data leaf, in resource tree
        order. Empty when the binary has no RT_ICON entries or all their leaves are
        dataless. The icons carry the primary language and sublanguage (split from the leaf id) and
        expose the same attributes add_resources() reads from lief.PE.ResourceIcon.
    """
    icons = []
    for top in binary.resources.childs:
        if top.id != lief.PE.ResourcesManager.TYPE.ICON.value:
            continue
        for icon_dir in top.childs:
            for leaf in icon_dir.childs:
                if leaf.is_data and len(leaf.content) > 0:
                    # The leaf id is the full language identifier; TreeIcon splits it into the
                    # primary language and sublanguage, like the manager icons expose them
                    icons.append(TreeIcon(icon_dir.id, leaf.id, bytes(leaf.content)))
    return icons


def lookup_signer_family(database, family_index=-1, sha1=None, sha256=None, md5=None, serial=None):
    results = []
    if sha1 is not None and "SHA1" in database:
        if sha1 in database["SHA1"]:
            results.append(("SHA1", sha1, database["SHA1"][sha1][family_index]))
    if sha256 is not None and "SHA256" in database:
        if sha256 in database["SHA256"]:
            results.append(("SHA256", sha256, database["SHA256"][sha256][family_index]))
    if md5 is not None and "MD5" in database:
        if md5 in database["MD5"]:
            results.append(("MD5", md5, database["MD5"][md5][family_index]))
    if serial is not None and "serial_number" in database:
        if serial in database["serial_number"]:
            results.append(("serial_number", serial, database["serial_number"][serial][family_index]))
    return results


def readable_size(value: int) -> str:
    """Return bytes in human readable format."""
    if value <= 1024:
        return "%s bytes" % value
    elif value < 1024 * 1024:
        return "%.1f KB" % (float(value) / 1024.0)
    elif value < 1024 * 1024 * 1024:
        return "%.1f MB" % (float(value) / 1024.0 / 1024.0)
    else:
        return "%.1f GB" % (float(value) / 1024.0 / 1024.0 / 1024.0)


class PE(ServiceBase):
    def start(self):
        self.log.debug("Starting PE")
        # Loading Rich header resolutions
        self.rich_header_entries = {}
        with open(os.path.join(pathlib.Path(__file__).parent.resolve(), "comp_id.txt"), "r") as f:
            for line in f.read().splitlines():
                if line and line[0] != "#":
                    k, v = line.split(" ", 1)
                    self.rich_header_entries[k] = v

        # Loading Code Signing Certificate Blocklist (CSCB)
        self.cscb = defaultdict(dict)
        with open(os.path.join(pathlib.Path(__file__).parent.resolve(), "cscb.csv"), "r", newline="") as csvfile:
            cscbreader = csv.reader(csvfile, quoting=csv.QUOTE_ALL, skipinitialspace=True)
            for row in cscbreader:
                if row[0].startswith("#"):
                    continue
                # row[1] = "serial_number"
                # row[2] = "thumbprint"
                # row[3] = "thumbprint_algorithm"
                # row[-1] = "Reason"
                self.cscb["serial_number"][row[1]] = row
                self.cscb[row[3]][row[2]] = row

        # Loading Revocation list from CertCentral
        self.certcentral = defaultdict(dict)
        with open(os.path.join(pathlib.Path(__file__).parent.resolve(), "certcentral.csv"), "r") as csvfile:
            certcentralreader = csv.reader(csvfile)
            headers = next(certcentralreader)
            serial_index = headers.index("Serial")
            # It looks to only have MD5 thumbprints
            thumbprint_index = headers.index("Thumbprint")
            self.certcentral_reason_index = headers.index("Malware")
            for row in certcentralreader:
                if row[0].startswith("#"):
                    continue
                self.certcentral["serial_number"][row[serial_index].lower()] = row
                lthumb = len(row[thumbprint_index])
                if lthumb == 32:
                    self.certcentral["MD5"][row[thumbprint_index].lower()] = row
                elif lthumb == 40:
                    self.certcentral["SHA1"][row[thumbprint_index].lower()] = row
                elif lthumb == 64:
                    self.certcentral["SHA256"][row[thumbprint_index].lower()] = row
                elif lthumb != 0:
                    self.log.warning(f"Could not figure out thumbprint hash type for {row[thumbprint_index]}")

        self.identify = forge.get_identify(use_cache=os.environ.get("PRIVILEGED", "false").lower() == "true")

    def check_timestamps(self):
        """Compares timestamps that could be found in the binary.

        Timestamp used:
            header timestamp
            load configuration timestamp
            export timestamp
            debug timestamp
            resources timestamps
        If any of them are different, raises a problem.
        Based on https://twitter.com/JusticeRage/status/1065921072367837185?s=09
        Examples :
        https://manalyzer.org/report/351d9ef64047f792aee0520ffd27a78a
            b166694232668792a8d5b63dd990711fe683b7899433dff0b4c8796457035b36
        https://manalyzer.org/report/6eff53e85a9ce9f1d99c812270093581
            effa0e01adad08ae4bc787678ce67510d013a06d1a10d39ec6b19e2449e25fbd
        https://manalyzer.org/report/be94c9506333481084e5fa46ccaee06c
            e15040beca2635a66eb395162f39db9f23468e7bf9f00c9c62dd5913cd5f3850
        """
        timestamps = set()
        delphi = False
        # In a reproducible build, the linker stamps a deterministic hash of the contents into
        # the header/debug/export/load configuration timestamp fields instead of build dates,
        # so those values cannot be compared or interpreted as dates. Resource timestamps are
        # kept, as they are not rewritten by the reproducible build process.
        repro = self.binary.is_reproducible_build
        if self.binary.header.time_date_stamps == 708992537:  # Likely a delphi binary
            delphi = True
        elif repro:
            pass
        elif self.binary.header.time_date_stamps != 0 and self.binary.header.time_date_stamps != 0xFFFFFFFF:
            timestamps.add(self.binary.header.time_date_stamps)

        if (
            not repro
            and self.binary.has_configuration
            and self.binary.load_configuration.timedatestamp != 0
            and self.binary.load_configuration.timedatestamp != 0xFFFFFFFF
        ):
            timestamps.add(self.binary.load_configuration.timedatestamp)

        if (
            not repro
            and self.binary.has_exports
            and self.binary.get_export().timestamp != 0
            and self.binary.get_export().timestamp != 0xFFFFFFFF
        ):
            timestamps.add(self.binary.get_export().timestamp)

        if not repro and self.binary.has_debug:
            for debug in self.binary.debug:
                if debug.timestamp != 0 and debug.timestamp != 0xFFFFFFFF:
                    timestamps.add(debug.timestamp)
                # Will never trigger, but taken from https://0xc0decafe.com/malware-analyst-guide-to-pe-timestamps/
                if isinstance(debug, lief.PE.CodeViewPDB) and debug.cv_signature.name == "01BN":
                    timestamps.add(debug.signature)

        def recurse_resources(node):
            if isinstance(node, lief.PE.ResourceDirectory):
                if node.time_date_stamp != 0 and node.time_date_stamp != 0xFFFFFFFF:
                    if delphi:
                        timestamps.add(from_msdos(node.time_date_stamp))
                    else:
                        timestamps.add(node.time_date_stamp)
                for child in node.childs:
                    recurse_resources(child)

        if self.binary.has_resources:
            recurse_resources(self.binary.resources)

        if len(timestamps) > 1 and max(timestamps) - min(timestamps) > self.config.get(
            "heur11_allowed_timestamp_range", 86400
        ):
            heur = Heuristic(11)
            heur_section = ResultSection(heur.name, heuristic=heur)
            for timestamp in timestamps:
                hr_timestamp = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S +00:00 (UTC)"
                )
                heur_section.add_line(f"{timestamp} ({hr_timestamp})")
            self.file_res.add_section(heur_section)
        if len(timestamps) > 0:
            heur22_earliest_ts = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
                days=self.config.get("heur22_flag_more_recent_than_days", 3)
            )
            heur22_latest_ts = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2)
            recent_timestamps = []
            future_timestamps = []
            for timestamp in sorted(timestamps):
                ts = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
                if ts < heur22_earliest_ts:
                    continue
                if ts > heur22_latest_ts:
                    future_timestamps.append((timestamp, ts))
                    continue
                recent_timestamps.append((timestamp, ts))

            if recent_timestamps:
                heur = Heuristic(22)
                heur_section = ResultSection(heur.name, heuristic=heur)
                for timestamp, ts in recent_timestamps:
                    heur_section.add_line(f"{timestamp} ({ts.strftime('%Y-%m-%d %H:%M:%S +00:00 (UTC)')})")
                self.file_res.add_section(heur_section)
            if future_timestamps:
                heur = Heuristic(26)
                heur_section = ResultSection(heur.name, heuristic=heur)
                for timestamp, ts in future_timestamps:
                    heur_section.add_line(f"{timestamp} ({ts.strftime('%Y-%m-%d %H:%M:%S +00:00 (UTC)')})")
                self.file_res.add_section(heur_section)

    def recurse_resources(self, resource, parent_name):
        if isinstance(resource, lief.PE.ResourceDirectory):
            if len(resource.childs) > 0:
                for child in resource.childs:
                    self.recurse_resources(child, f"{parent_name}{resource.id}_")
        elif isinstance(resource, lief.PE.ResourceData):
            if resource.content[:2] == MZ or search_list_in_list(DOS_MODE, resource.content[:200].tolist()):
                if len(resource.content) < self.config.get("heur12_min_size_byte", 60):
                    return
                file_name = f"binary_{parent_name}{resource.id}"
                self.extracted_file_from_resources.append(file_name)
                temp_path = os.path.join(self.working_directory, file_name)
                with open(temp_path, "wb") as myfile:
                    myfile.write(bytearray(resource.content))
                self.request.add_extracted(
                    temp_path,
                    file_name,
                    f"{file_name} extracted from binary's resources",
                    safelist_interface=self.api_interface,
                )

    def check_exe_resources(self):
        self.extracted_file_from_resources = []
        if self.binary.has_resources:
            self.recurse_resources(self.binary.resources, "")
        if self.extracted_file_from_resources:
            temp_res = ResultSection("Executable in resources", heuristic=Heuristic(12))
            for file_name in self.extracted_file_from_resources:
                temp_res.add_line(f"Extracted {file_name}")
            self.file_res.add_section(temp_res)

    def check_dataless_resources(self):
        dataless_resources = []

        def recurse_resources(node, parent_name):
            if node.is_directory:
                if len(node.childs) > 0:
                    for child in node.childs:
                        recurse_resources(child, f"{parent_name}{node.id} -> ")
                else:
                    dataless_resources.append(f"{parent_name}{node.id}")

        if self.binary.has_resources:
            recurse_resources(self.binary.resources, "")

        if len(dataless_resources) > 0:
            res = ResultSection("Resource directories that does not contain a leaf data node", heuristic=Heuristic(15))
            res.add_lines(dataless_resources)
            self.file_res.add_section(res)

    def add_headers(self):
        # compute PE machine header feature. Called twice
        pe_machine = parse_machine_type(self.binary.header)

        self.features["name"] = os.path.basename(self.file_path)  # Removed in 0.14.0
        self.features["format"] = self.binary.format.name
        self.features["imphash"] = lief.PE.get_imphash(self.binary, mode=lief.PE.IMPHASH_MODE.PEFILE)
        # Somehow, that is different from binary.entrypoint
        self.features["entrypoint"] = self.binary.optional_header.addressof_entrypoint
        self.features["header"] = {
            "characteristics_hash": self.binary.header.characteristics,
            "characteristics_list": [char.name for char in self.binary.header.characteristics_list],
            "machine": pe_machine,
            "numberof_sections": self.binary.header.numberof_sections,
            "numberof_symbols": self.binary.header.numberof_symbols,
            "signature": self.binary.header.signature,
            "timestamp": self.binary.header.time_date_stamps,
        }
        self.features["optional_header"] = {
            "addressof_entrypoint": self.binary.optional_header.addressof_entrypoint,
            "baseof_code": self.binary.optional_header.baseof_code,
            "checksum": self.binary.optional_header.checksum,
            "dll_characteristics": self.binary.optional_header.dll_characteristics,
            "dll_characteristics_lists": [char.name for char in self.binary.optional_header.dll_characteristics_lists],
            "file_alignment": self.binary.optional_header.file_alignment,
            "imagebase": self.binary.optional_header.imagebase,
            "loader_flags": self.binary.optional_header.loader_flags,
            "magic": get_lief_enum_name(self.binary.optional_header.magic),
            "major_image_version": self.binary.optional_header.major_image_version,
            "major_linker_version": self.binary.optional_header.major_linker_version,
            "major_operating_system_version": self.binary.optional_header.major_operating_system_version,
            "major_subsystem_version": self.binary.optional_header.major_subsystem_version,
            "minor_image_version": self.binary.optional_header.minor_image_version,
            "minor_linker_version": self.binary.optional_header.minor_linker_version,
            "minor_operating_system_version": self.binary.optional_header.minor_operating_system_version,
            "minor_subsystem_version": self.binary.optional_header.minor_subsystem_version,
            "numberof_rva_and_size": self.binary.optional_header.numberof_rva_and_size,
            "section_alignment": self.binary.optional_header.section_alignment,
            "sizeof_code": self.binary.optional_header.sizeof_code,
            "sizeof_headers": self.binary.optional_header.sizeof_headers,
            "sizeof_heap_commit": self.binary.optional_header.sizeof_heap_commit,
            "sizeof_heap_reserve": self.binary.optional_header.sizeof_heap_reserve,
            "sizeof_image": self.binary.optional_header.sizeof_image,
            "sizeof_initialized_data": self.binary.optional_header.sizeof_initialized_data,
            "sizeof_stack_commit": self.binary.optional_header.sizeof_stack_commit,
            "sizeof_stack_reserve": self.binary.optional_header.sizeof_stack_reserve,
            "sizeof_uninitialized_data": self.binary.optional_header.sizeof_uninitialized_data,
            "subsystem": get_lief_enum_name(self.binary.optional_header.subsystem),
            "win32_version_value": self.binary.optional_header.win32_version_value,
        }
        if self.binary.optional_header.magic == lief.PE.PE_TYPE.PE32:
            self.features["optional_header"]["baseof_data"] = self.binary.optional_header.baseof_data
        self.features["dos_header"] = {
            "addressof_new_exeheader": self.binary.dos_header.addressof_new_exeheader,
            "addressof_relocation_table": self.binary.dos_header.addressof_relocation_table,
            "checksum": self.binary.dos_header.checksum,
            "file_size_in_pages": self.binary.dos_header.file_size_in_pages,
            "header_size_in_paragraphs": self.binary.dos_header.header_size_in_paragraphs,
            "initial_ip": self.binary.dos_header.initial_ip,
            "initial_relative_cs": self.binary.dos_header.initial_relative_cs,
            "initial_relative_ss": self.binary.dos_header.initial_relative_ss,
            "initial_sp": self.binary.dos_header.initial_sp,
            "magic": self.binary.dos_header.magic,
            "maximum_extra_paragraphs": self.binary.dos_header.maximum_extra_paragraphs,
            "minimum_extra_paragraphs": self.binary.dos_header.minimum_extra_paragraphs,
            "numberof_relocation": self.binary.dos_header.numberof_relocation,
            "oem_id": self.binary.dos_header.oem_id,
            "oem_info": self.binary.dos_header.oem_info,
            "overlay_number": self.binary.dos_header.overlay_number,
            "used_bytes_in_the_last_page": self.binary.dos_header.used_bytes_in_last_page,
        }

        if self.binary.has_rich_header:
            self.features["rich_header"] = {
                "entries": [
                    {
                        "build_id": entry.build_id,
                        "count": entry.count,
                        "entry_id": entry.id,
                    }
                    for entry in self.binary.rich_header.entries
                ],
                "key": self.binary.rich_header.key,
            }
        if self.binary.has_exceptions:
            # TODO: What is this has_exceptions supposed to be linked to?
            # A lot of executables seems to have this flag set to True
            pass

        # TODO: Do we want to show them all?
        # print(self.binary.exception_functions)
        # print(self.binary.functions)
        # print(self.binary.imported_functions)
        # print(self.binary.exported_functions)

        self.features["nx"] = self.binary.has_nx

        self.features["authentihash"] = {}

        if self.binary.has_tls:
            if self.binary.tls.has_section:
                if isinstance(self.binary.tls.section.name, str):
                    section_name = self.binary.tls.section.name
                else:
                    section_name = self.binary.tls.section.name.decode("utf-8", "backslashreplace")
                self.features["tls"] = {"section": section_name}
            elif self.binary.tls.has_data_directory:
                if self.binary.tls.directory.has_section:
                    if isinstance(self.binary.tls.directory.section.name, str):
                        section_name = self.binary.tls.directory.section.name
                    else:
                        section_name = self.binary.tls.directory.section.name.decode("utf-8", "backslashreplace")
                    self.features["tls"] = {"section": section_name}

        # print(self.binary.imagebase) # Doesn't work as documented?
        self.features["position_independent"] = self.binary.is_pie
        self.features["is_reproducible_build"] = self.binary.is_reproducible_build
        self.features["size_of_headers"] = self.binary.sizeof_headers
        self.features["virtual_size"] = self.binary.virtual_size
        self.features["size"] = os.path.getsize(self.file_path)
        # Ignore self.binary.symbols

        res = ResultOrderedKeyValueSection("Headers")
        hr_timestamp = datetime.datetime.utcfromtimestamp(self.binary.header.time_date_stamps).strftime(
            "%Y-%m-%d %H:%M:%S +00:00 (UTC)"
        )
        res.add_tag("file.pe.linker.timestamp", self.binary.header.time_date_stamps)
        if self.binary.is_reproducible_build:
            # The linker of reproducible builds stamps a content hash instead of a build date
            res.add_item("Timestamp", f"{self.binary.header.time_date_stamps} (reproducibility hash, not a build date)")
        else:
            res.add_item("Timestamp", f"{self.binary.header.time_date_stamps} ({hr_timestamp})")
            res.add_tag("file.pe.linker.timestamp", hr_timestamp)
        # Somehow, that is different from binary.entrypoint
        res.add_item("Entrypoint", hex(self.binary.optional_header.addressof_entrypoint))
        res.add_tag("file.pe.oep.hexdump", hex(self.binary.optional_header.addressof_entrypoint))
        res.add_item("Machine", pe_machine)
        magic_name = get_lief_enum_name(self.binary.optional_header.magic)
        if isinstance(magic_name, int):
            res.add_item("Magic", "???")
            heur = Heuristic(18)
            heur_section = ResultOrderedKeyValueSection(heur.name, heuristic=heur)
            heur_section.add_item("Magic Name", "???")
            heur_section.add_item("Magic Value", magic_name)
            res.add_subsection(heur_section)
        else:
            res.add_item("Magic", magic_name)
        res.add_item(
            "Image version",
            f"{self.binary.optional_header.major_image_version}.{self.binary.optional_header.minor_image_version}",
        )
        res.add_item(
            "Linker version",
            f"{self.binary.optional_header.major_linker_version}.{self.binary.optional_header.minor_linker_version}",
        )
        res.add_item(
            "Operating System version",
            (
                f"{self.binary.optional_header.major_operating_system_version}."
                f"{self.binary.optional_header.minor_operating_system_version}"
            ),
        )
        res.add_item(
            "Subsystem version",
            (
                f"{self.binary.optional_header.major_subsystem_version}."
                f"{self.binary.optional_header.minor_subsystem_version}"
            ),
        )
        res.add_item("Subsystem", get_lief_enum_name(self.binary.optional_header.subsystem))
        res.add_item("NX", self.binary.has_nx)
        if self.binary.has_rich_header:
            rich_header_section = ResultMultiSection(f"Rich Headers - Key: {self.binary.rich_header.key}")
            # Recreate the rich header original clear data to compute the rich header hash
            clear_data = ""

            table_body = TableSectionBody()
            for entry in self.binary.rich_header.entries:
                clear_data = (
                    f"{entry.build_id.to_bytes(2, byteorder='little').hex()}"
                    f"{entry.id.to_bytes(2, byteorder='little').hex()}"
                    f"{entry.count.to_bytes(4, byteorder='little').hex()}"
                    f"{clear_data}"
                )
                rich_header_hex = (
                    f"{entry.id.to_bytes(2, byteorder='big').hex()}{entry.build_id.to_bytes(2, byteorder='big').hex()}"
                )
                try:
                    entry_compilation_info = self.rich_header_entries[rich_header_hex]
                    table_body.add_row(
                        TableRow(
                            **{
                                "ID": f"0x{rich_header_hex}",
                                "Compiler Information": entry_compilation_info,
                                "Count": entry.count,
                            }
                        )
                    )
                except KeyError:
                    table_body.add_row(
                        TableRow(
                            **{
                                "ID": f"0x{rich_header_hex}",
                                "Compiler Information": f"Unknown object 0x{rich_header_hex}",
                                "Count": entry.count,
                            }
                        )
                    )

            clear_data = bytes.fromhex(f"44616e53{'0' * 24}{clear_data}")  # DanS
            m = hashlib.md5()
            m.update(clear_data)
            rich_header_hash = m.hexdigest()
            kv_body = OrderedKVSectionBody()
            kv_body.add_item("Hash", rich_header_hash)
            rich_header_section.add_section_part(kv_body)
            rich_header_section.add_tag("file.pe.rich_header.hash", rich_header_hash)
            self.features["rich_header"]["hash"] = rich_header_hash
            rich_header_section.add_section_part(table_body)
            res.add_subsection(rich_header_section)

        if abs(self.features["size"] - self.features["virtual_size"]) > max(
            self.features["size"], self.features["virtual_size"]
        ) * self.config.get("heur24_allowed_mismatch_file_size", 0.25):
            heur = Heuristic(24)
            heur_section = ResultOrderedKeyValueSection(heur.name, heuristic=heur)
            heur_section.add_item("File Size", f"{self.features['size']} ({readable_size(self.features['size'])})")
            heur_section.add_item(
                "Virtual Size", f"{self.features['virtual_size']} ({readable_size(self.features['virtual_size'])})"
            )
            res.add_subsection(heur_section)

        sub_res = ResultOrderedKeyValueSection("Authentihash")
        for i in range(1, 6):
            authentihash = lief.PE.ALGORITHMS(i).name.replace("_", "").lower()
            authentihash_value = self.binary.authentihash(lief.PE.ALGORITHMS(i)).hex()
            if not authentihash_value:
                # LIEF returns no hash on some corrupted files (e.g. an overlay present while the
                # data directories are truncated before the certificate table).
                if sub_res.heuristic is None:
                    sub_res.set_heuristic(17)
                continue
            self.features["authentihash"][authentihash] = authentihash_value
            sub_res.add_item(authentihash, authentihash_value)
        res.add_subsection(sub_res)

        res.add_item("Position Independent", self.binary.is_pie)

        res.add_item("Checksum", f"{self.features['optional_header']['checksum']:#0{10}x}")
        if self.features["size"] <= self.config.get("hash_generation_max_size", 5000000) or self.request.deep_scan:
            self.features["optional_header"]["computed_checksum"] = generate_checksum(
                self.request.file_path, self.binary.dos_header.addressof_new_exeheader + 0x58
            )
            if (
                self.features["optional_header"]["checksum"] != 0
                and self.features["optional_header"]["checksum"]
                != self.features["optional_header"]["computed_checksum"]
            ):
                heur = Heuristic(23)
                heur_section = ResultOrderedKeyValueSection(heur.name, heuristic=heur)
                heur_section.add_item(
                    "Optional header checksum", f"{self.features['optional_header']['checksum']:#0{10}x}"
                )
                heur_section.add_item(
                    "Computed checksum", f"{self.features['optional_header']['computed_checksum']:#0{10}x}"
                )
                res.add_subsection(heur_section)

        self.file_res.add_section(res)

    def add_sections(self):
        res = ResultSection("Sections")
        self.features["sections"] = []
        if len(self.binary.sections) == 0:
            res.add_line("0 sections found in executable")
            res.set_heuristic(19)
        is_text_section_executable = False
        are_non_text_sections_executable = False
        for section in self.binary.sections:
            if section.size > len(section.content):
                full_section_data = bytearray(section.content) + section.padding
            else:
                full_section_data = bytearray(section.content)

            entropy_data = calculate_partition_entropy(BytesIO(full_section_data))
            if isinstance(section.name, str):
                section_name = section.name
            else:
                section_name = section.name.decode("utf-8", "backslashreplace")

            section_dict = {
                "name": section_name,
                "characteristics_hash": section.characteristics,
                "characteristics_list": [char.name for char in section.characteristics_lists],
                "entropy": entropy_data[0],
                "entropy_without_padding": section.entropy,
                "md5": hashlib.md5(full_section_data).hexdigest(),
                "offset": section.offset,
                "size": section.size,
                "sizeof_raw_data": section.sizeof_raw_data,
                "virtual_address": section.virtual_address,
                "virtual_size": section.virtual_size,
            }
            try:
                if hasattr(section, "fullname"):
                    section_dict["fullname"] = section.fullname.decode("utf-8", "backslashreplace")
            except UnicodeDecodeError:
                pass

            self.features["sections"].append(section_dict)

            section_section = ResultMultiSection(f"Section - {section_name}")
            if section_name in PACKED_SECTION_NAMES:
                heur = Heuristic(20)
                heur_section = ResultSection(heur.name, heuristic=heur)
                heur_section.add_line(f"Section name: {section_name}")
                section_section.add_subsection(heur_section)
            elif section_name.lower() in NON_STANDARD_SECTION_NAMES:
                heur = Heuristic(34)
                heur_section = ResultSection(heur.name, heuristic=heur)
                heur_section.add_line(f"Section name: {section_name}")
                section_section.add_subsection(heur_section)
            for malicious_section in MALICIOUS_SECTION_NAMES:
                if section_name == malicious_section[0] and (
                    malicious_section[1] is None or section.characteristics == malicious_section[1]
                ):
                    heur = Heuristic(21)
                    heur_section = ResultSection(heur.name, heuristic=heur)
                    heur_section.add_line(f"Section name: {section_name}")
                    if malicious_section[1] is not None:
                        heur_section.add_line(f"Characteristics: {', '.join(section_dict['characteristics_list'])}")
                    section_section.add_subsection(heur_section)
            section_section.add_tag("file.pe.sections.name", section_name)
            section_text_section = OrderedKVSectionBody()
            section_text_section.add_item("Entropy", entropy_data[0])
            section_graph_section = GraphSectionBody()
            section_graph_section.set_colormap(cmap_min=0, cmap_max=8, values=[round(x, 5) for x in entropy_data[1]])
            # Supported by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e38/pe.py#L1097
            # Supported by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e3/lief.py#L363
            if entropy_data[0] > self.config.get("heur4_max_section_entropy", 7.5):
                heur = Heuristic(4)
                heur_section = ResultMultiSection(heur.name, heuristic=heur)
                heur_text_section = OrderedKVSectionBody()
                heur_text_section.add_item("Section name", section_name)
                heur_text_section.add_item("Entropy:", entropy_data[0])
                heur_text_section.add_item("Entropy without padding", section.entropy)
                heur_section.add_section_part(heur_text_section)
                heur_section.add_section_part(section_graph_section)
                section_section.add_subsection(heur_section)
            section_text_section.add_item("Entropy without padding", section.entropy)
            section_text_section.add_item("Offset", section.offset)
            section_text_section.add_item("Size", section.size)
            section_text_section.add_item("Virtual Size", section.virtual_size)
            section_text_section.add_item("Characteristics", ", ".join(section_dict["characteristics_list"]))
            section_text_section.add_item("MD5", section_dict["md5"])
            section_section.add_tag("file.pe.sections.hash", section_dict["md5"])
            section_section.add_section_part(section_text_section)
            section_section.add_section_part(section_graph_section)

            try:
                self.binary.get_section(section.name)
            except Exception:  # lief.not_found:
                raise
                heur = Heuristic(14)
                heur_section = ResultMultiSection(heur.name, heuristic=heur)
                heur_text_body = TextSectionBody()
                heur_text_body.add_line("Section could not be retrieved using the section's name.")
                heur_section.add_section_part(heur_text_body)
                heur_kv_body = OrderedKVSectionBody()
                heur_kv_body.add_item("Section name", section_name)
                heur_section.add_section_part(heur_kv_body)
                section_section.add_subsection(heur_section)

            if section_name == ".text" and any(
                "EXECUTE".lower() in characteristic.lower() for characteristic in section_dict["characteristics_list"]
            ):
                is_text_section_executable = True

            elif section_name != ".text" and any(
                "EXECUTE".lower() in characteristic.lower() for characteristic in section_dict["characteristics_list"]
            ):
                are_non_text_sections_executable = True

            res.add_subsection(section_section)

        # As per https://learn.microsoft.com/en-ca/windows/win32/debug/pe-format?redirectedfrom=MSDN, the main
        # executable code section is .text, with the IMAGE_SCN_MEM_EXECUTE flag. So this is expected. What is not
        # expected, however, is if .text is executable, AS WELL AS another section
        if is_text_section_executable and are_non_text_sections_executable:
            text_exec_heur = Heuristic(33)
            _ = ResultSection(text_exec_heur.name, heuristic=text_exec_heur, parent=res)

        empty_names = [section.name for section in self.binary.sections if section.name.strip() == ""]
        if empty_names:
            heur = Heuristic(20)
            heur_section = ResultSection(heur.name, heuristic=heur)
            if len(empty_names) > 1:
                heur_section.add_line(f"PE contains {len(empty_names)} empty section names.")
            else:
                heur_section.add_line("PE contains an empty section name.")
            res.add_subsection(heur_section)

        self.file_res.add_section(res)

    def add_debug(self):
        if not self.binary.has_debug:
            return
        self.features["debugs"] = []
        res = ResultSection("Debugs")
        for debug in self.binary.debug:
            debug_dict = {
                "addressof_rawdata": debug.addressof_rawdata,
                "characteristics": debug.characteristics,
                "major_version": debug.major_version,
                "minor_version": debug.minor_version,
                "pointerto_rawdata": debug.pointerto_rawdata,
                "sizeof_data": debug.sizeof_data,
                "timestamp": debug.timestamp,
                "type": get_lief_enum_name(debug.type),
            }
            sub_res = ResultOrderedKeyValueSection(f"{debug_dict['type']}")
            hr_timestamp = datetime.datetime.utcfromtimestamp(debug.timestamp).strftime(
                "%Y-%m-%d %H:%M:%S +00:00 (UTC)"
            )
            sub_res.add_item("Timestamp", f"{debug.timestamp} ({hr_timestamp})")
            sub_res.add_item("Version", f"{debug.major_version}.{debug.minor_version}")
            if isinstance(debug, lief.PE.CodeViewPDB):
                cv_dict = {
                    "age": debug.age,
                    "cv_signature": debug.cv_signature.name,
                    "guid": (
                        f"{''.join([hex(x)[2:] for x in debug.signature[:4][::-1]])}-"
                        f"{''.join([hex(x)[2:] for x in debug.signature[4:6][::-1]])}-"
                        f"{''.join([hex(x)[2:] for x in debug.signature[6:8][::-1]])}-"
                        f"{''.join([hex(x)[2:] for x in debug.signature[8:10]])}-"
                        f"{''.join([hex(x)[2:] for x in debug.signature[10:]])}"
                    ),
                }
                sub_res.add_item("CV_Signature", debug.cv_signature.name)
                try:
                    if isinstance(debug.filename, str):
                        debug_filename = debug.filename
                    else:
                        debug_filename = debug.filename.decode("utf-8", "backslashreplace")
                    cv_dict["filename"] = debug_filename
                    sub_res.add_item("Filename", debug_filename)
                    sub_res.add_tag("file.pe.pdb_filename", debug_filename)
                    heur = Heuristic(38)
                    heur_section = ResultSection(heur.name, heuristic=heur)
                    lower_debug_filename = debug_filename.lower()
                    for kw in self.config.get("pdb_keywords", []):
                        if kw in lower_debug_filename:
                            heur_section.add_line(kw)
                    if heur_section.body:
                        sub_res.add_subsection(heur_section)
                except UnicodeDecodeError:
                    heur = Heuristic(16)
                    heur_section = ResultSection(heur.name, heuristic=heur)
                    sub_res.add_subsection(heur_section)
                sub_res.add_item("GUID", cv_dict["guid"])
                sub_res.add_tag("file.pe.debug.guid", cv_dict["guid"])
                debug_dict["code_view"] = cv_dict
            if isinstance(debug, lief.PE.Pogo):
                debug_dict["pogo"] = {
                    "entries": [],
                    "signature": get_lief_enum_name(debug.signature),
                }
                sub_sub_res = ResultSection(f"POGO - {debug_dict['pogo']['signature']}")
                for entry in debug.entries:
                    entry_name = (
                        entry.name if isinstance(entry.name, str) else entry.name.decode("utf-8", "backslashreplace")
                    )
                    debug_dict["pogo"]["entries"].append(
                        {
                            "name": entry_name,
                            "size": entry.size,
                            "start_rva": entry.start_rva,
                        }
                    )
                    sub_sub_res.add_line(f"Name: {entry_name}, Size: {entry.size}")
                sub_res.add_subsection(sub_sub_res)
            self.features["debugs"].append(debug_dict)
            res.add_subsection(sub_res)
        self.file_res.add_section(res)

    def add_exports(self):
        if not self.binary.has_exports:
            return
        res = ResultSection("Export")

        export = self.binary.get_export()
        self.features["export"] = {
            "entries": [],
            "export_flags": export.export_flags,
            "major_version": export.major_version,
            "minor_version": export.minor_version,
            "name": export.name,
            "ordinal_base": export.ordinal_base,
            "timestamp": export.timestamp,
        }

        res.add_line(f"Name: {export.name}")
        res.add_tag("file.pe.exports.module_name", export.name)
        res.add_line(f"Version: {export.major_version}.{export.minor_version}")
        hr_timestamp = datetime.datetime.utcfromtimestamp(export.timestamp).strftime("%Y-%m-%d %H:%M:%S +00:00 (UTC)")
        res.add_line(f"Timestamp: {export.timestamp} ({hr_timestamp})")

        sub_res = ResultSection("Entries", parent=res)
        unparsed_forward_information = []
        for entry in export.entries:
            entry_name = entry.name
            if isinstance(entry_name, bytes):
                entry_name = entry_name.decode("utf-8", "backslashreplace")
            entry_dict = {
                "address": entry.address,
                "forward_information": None,
                "function_rva": entry.function_rva,
                "is_extern": entry.is_extern,
                "name": entry_name,
                "ordinal": entry.ordinal,
                # "size": entry.size, #In the docs, but not in the dir()
                # "value": entry.value, #In the docs, but not in the dir()
            }
            if len(self.features["export"]["entries"]) < 100:
                sub_res.add_line(f"Name: {entry_name}, ordinal: {entry.ordinal}")
                sub_res.add_tag("file.pe.exports.function_name", entry_name)

            try:
                entry_dict["forward_information"] = {
                    "function": entry.forward_information.function,
                    "library": entry.forward_information.library,
                }
            except UnicodeDecodeError:
                del entry_dict["forward_information"]
                unparsed_forward_information.append((entry_name, entry.ordinal))
            self.features["export"]["entries"].append(entry_dict)

        if unparsed_forward_information:
            heur = Heuristic(13)
            heur_section = ResultSection(heur.name, heuristic=heur, parent=sub_res)
            for entry_name, entry_ordinal in unparsed_forward_information:
                heur_section.add_line(f"Couldn't parse the forward information of {entry_name} ({entry_ordinal})")

        if len(self.features["export"]["entries"]) > 100:
            heur = Heuristic(30)
            heur_section = ResultSection(heur.name, heuristic=heur, parent=res)
            heur_section.add_line(
                f"A total of {len(self.features['export']['entries'])} exports found, but only the first 100 are shown."
            )
            if export.name == "node.exe":
                heur = Heuristic(31)
                heur_section = ResultSection(heur.name, heuristic=heur, parent=res, body=heur.description)

        self.file_res.add_section(res)

    def add_imports(self):
        if not self.binary.has_imports:
            # Supported by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e3/lief.py#L454
            no_imports_heur = Heuristic(32)
            _ = ResultSection(no_imports_heur.name, heuristic=no_imports_heur, parent=self.file_res)
            return

        self.features["imports"] = defaultdict(list)
        for lib in self.binary.imports:
            for entry in lib.entries:
                entry_dict = {
                    "data": entry.data,
                    "hint": entry.hint,
                    "iat_address": entry.iat_address,
                    "iat_value": entry.iat_value,
                    "is_ordinal": entry.is_ordinal,
                    "name": entry.name,
                }
                if entry.is_ordinal:
                    entry_dict["ordinal"] = entry.ordinal
                self.features["imports"][lib.name].append(entry_dict)

        res = ResultSection("Imports")
        for lib_name, entries in self.features["imports"].items():
            sub_res = ResultSection(f"{lib_name}")
            sub_res.add_line(
                ", ".join([str(entry["ordinal"]) if entry["is_ordinal"] else str(entry["name"]) for entry in entries])
            )
            res.add_subsection(sub_res)
        res.add_tag("file.pe.imports.sorted_sha1", calc_imphash_sha1(self.features["imports"]))
        res.add_tag("file.pe.imports.imphash", self.features["imphash"])
        res.add_tag("file.pe.imports.fuzzy", calc_impfuzzy(self.features["imports"], sort=False))
        res.add_tag("file.pe.imports.sorted_fuzzy", calc_impfuzzy(self.features["imports"], sort=True))

        cmd = ["./pe/c_gimphash_linux", self.file_path]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0 and len(proc.stderr) == 0:
            output = proc.stdout.split()
            if len(output) == 2 and len(output[0]) == 64:
                res.add_tag("file.pe.imports.gimphash", output[0])

        self.file_res.add_section(res)

    def add_configuration(self):
        if not self.binary.has_configuration:
            return

        load_configuration = self.binary.load_configuration
        load_configuration_dict = {
            "characteristics": load_configuration.characteristics,
            "critical_section_default_timeout": load_configuration.critical_section_default_timeout,
            "csd_version": load_configuration.csd_version,
            "decommit_free_block_threshold": load_configuration.decommit_free_block_threshold,
            "decommit_total_free_threshold": load_configuration.decommit_total_free_threshold,
            "editlist": load_configuration.editlist,
            "global_flags_clear": load_configuration.global_flags_clear,
            "global_flags_set": load_configuration.global_flags_set,
            "lock_prefix_table": load_configuration.lock_prefix_table,
            "major_version": load_configuration.major_version,
            "maximum_allocation_size": load_configuration.maximum_allocation_size,
            "minor_version": load_configuration.minor_version,
            "process_affinity_mask": load_configuration.process_affinity_mask,
            "process_heap_flags": load_configuration.process_heap_flags,
            "reserved1": load_configuration.reserved1,
            "security_cookie": load_configuration.security_cookie,
            "timedatestamp": load_configuration.timedatestamp,
            "virtual_memory_threshold": load_configuration.virtual_memory_threshold,
            "se_handler_count": load_configuration.se_handler_count,
            "se_handler_table": load_configuration.se_handler_table,
            "guard_cf_check_function_pointer": load_configuration.guard_cf_check_function_pointer,
            "guard_cf_dispatch_function_pointer": load_configuration.guard_cf_dispatch_function_pointer,
            "guard_cf_function_count": load_configuration.guard_cf_function_count,
            "guard_cf_function_table": load_configuration.guard_cf_function_table,
            "guard_address_taken_iat_entry_count": load_configuration.guard_address_taken_iat_entry_count,
            "guard_address_taken_iat_entry_table": load_configuration.guard_address_taken_iat_entry_table,
            "guard_long_jump_target_count": load_configuration.guard_long_jump_target_count,
            "guard_long_jump_target_table": load_configuration.guard_long_jump_target_table,
            "dynamic_value_reloc_table": load_configuration.dynamic_value_reloc_table,
            "hybrid_metadata_pointer": load_configuration.hybrid_metadata_pointer,
            "dynamic_value_reloctable_offset": load_configuration.dynamic_value_reloctable_offset,
            "dynamic_value_reloctable_section": load_configuration.dynamic_value_reloctable_section,
            "guard_rf_failure_routine": load_configuration.guard_rf_failure_routine,
            "guard_rf_failure_routine_function_pointer": load_configuration.guard_rf_failure_routine_function_pointer,
            "reserved2": load_configuration.reserved2,
            "guard_rf_verify_stackpointer_function_pointer": (
                load_configuration.guard_rf_verify_stackpointer_function_pointer
            ),
            "hotpatch_table_offset": load_configuration.hotpatch_table_offset,
            "reserved3": load_configuration.reserved3,
            "enclave_configuration_ptr": load_configuration.enclave_configuration_ptr,
            "volatile_metadata_pointer": load_configuration.volatile_metadata_pointer,
            "guard_eh_continuation_count": load_configuration.guard_eh_continuation_count,
            "guard_eh_continuation_table": load_configuration.guard_eh_continuation_table,
            "guard_xfg_check_function_pointer": load_configuration.guard_xfg_check_function_pointer,
            "guard_xfg_dispatch_function_pointer": load_configuration.guard_xfg_dispatch_function_pointer,
            "guard_xfg_table_dispatch_function_pointer": load_configuration.guard_xfg_table_dispatch_function_pointer,
            "cast_guard_os_determined_failure_mode": load_configuration.cast_guard_os_determined_failure_mode,
            "guard_memcpy_function_pointer": load_configuration.guard_memcpy_function_pointer,
            "uma_function_pointers": load_configuration.uma_function_pointers,
        }
        if load_configuration.guard_cf_flags_list is not None:
            load_configuration_dict["guard_cf_flags_list"] = [
                guard_flag.name for guard_flag in load_configuration.guard_cf_flags_list
            ]
        if load_configuration.guard_flags is not None:
            # report the known flag names and keep any undocumented bits as hex
            # since IMAGE_GUARD is a strict flag that rejects unknown bits
            guard_flags = load_configuration.guard_flags
            image_guard = lief.PE.LoadConfiguration.IMAGE_GUARD
            known_mask = 0
            for flag in image_guard:
                known_mask |= flag.value
            parts = []
            if guard_flags & known_mask:
                parts.append(image_guard(guard_flags & known_mask).name)
            if guard_flags & ~known_mask:
                parts.append(hex(guard_flags & ~known_mask))
            load_configuration_dict["guard_flags"] = "|".join(parts) if parts else str(guard_flags)
        if load_configuration.code_integrity is not None:
            load_configuration_dict["code_integrity"] = {
                "catalog": load_configuration.code_integrity.catalog,
                "catalog_offset": load_configuration.code_integrity.catalog_offset,
                "flags": load_configuration.code_integrity.flags,
                "reserved": load_configuration.code_integrity.reserved,
            }

        # Fields that no longer exist in the PE format may be None; the ontology model marks them all Optional
        load_configuration_dict = {k: v for k, v in load_configuration_dict.items() if v is not None}

        self.features["load_configuration"] = load_configuration_dict

    def add_resources(self):
        if not self.binary.has_resources:
            heur = Heuristic(35)
            ResultSection(heur.name, heuristic=heur, parent=self.file_res)
            return

        # Keep the manager alive for the whole method: in LIEF, objects handed out by the
        # ResourcesManager (dialogs, icons, ...) are tied to its lifetime, and iterating
        # them off a temporary manager crashes the interpreter.
        resources_manager = self.binary.resources_manager

        # TODO: Find all the langs/sublangs
        self.features["resources_manager"] = {
            "langs_available": [],
            "sublangs_available": [],
        }
        res = ResultOrderedKeyValueSection("Resources")

        if resources_manager.has_accelerator:
            self.features["resources_manager"]["accelerators"] = []
            for accelerator in resources_manager.accelerator:
                accelerator_dict = {
                    "accelerator_id": accelerator.id,
                    "padding": accelerator.padding,
                }
                try:
                    accelerator_dict["ansi"] = lief.PE.ACCELERATOR_CODES(accelerator.ansi).name
                except ValueError:
                    accelerator_dict["ansi"] = "???"
                except TypeError:
                    pass
                try:
                    accelerator_dict["flags"] = " | ".join(
                        [accelerator_flags_entries[x].name for x in get_powers(accelerator.flags)]
                    )
                except KeyError:
                    pass
                self.features["resources_manager"]["accelerators"].append(accelerator_dict)

        if resources_manager.has_dialogs:
            corrupted_dialog_section = None
            dialogs_list = []
            for dialog in resources_manager.dialogs:
                is_extended = dialog.type == lief.PE.ResourceDialog.TYPE.EXTENDED
                dialog_dict = {
                    "cx": dialog.cx,
                    "cy": dialog.cy,
                    "dialogbox_style_list": sorted([dialogbox_style.name for dialogbox_style in dialog.styles_list]),
                    "extended_style": str(dialog.extended_style),
                    "extended_style_list": sorted(
                        [extended_style.name for extended_style in dialog.windows_ext_styles_list]
                    ),
                    "items": [],
                    "style": str(dialog.style),
                    "style_list": sorted([style.name for style in dialog.windows_styles_list]),
                    "title": "",
                    "x": dialog.x,
                    "y": dialog.y,
                }
                if is_extended:
                    dialog_dict["help_id"] = dialog.help_id
                    dialog_dict["signature"] = dialog.signature
                    dialog_dict["version"] = dialog.version
                font = dialog.font
                if font is not None:
                    dialog_dict["point_size"] = font.point_size
                    if is_extended:
                        dialog_dict["charset"] = font.charset
                        dialog_dict["weight"] = font.weight
                    try:
                        dialog_dict["typeface"] = font.typeface if is_extended else font.name
                    except UnicodeDecodeError:
                        if corrupted_dialog_section is None:
                            heur = Heuristic(13)
                            corrupted_dialog_section = ResultSection(heur.name, heuristic=heur, parent=res)
                        corrupted_dialog_section.add_line("Can't decode typeface of dialog")
                try:
                    dialog_dict["title"] = dialog.title
                    if dialog.title != "":
                        res.add_tag("file.string.extracted", dialog.title)
                except UnicodeDecodeError:
                    del dialog_dict["title"]
                    if corrupted_dialog_section is None:
                        heur = Heuristic(13)
                        corrupted_dialog_section = ResultSection(heur.name, heuristic=heur, parent=res)
                    corrupted_dialog_section.add_line("Can't decode main title of dialog")

                for item in dialog.items:
                    item_dict = {
                        "cx": item.cx,
                        "cy": item.cy,
                        "extended_style": item.extended_style,
                        "item_id": item.id,
                        "is_extended": is_extended,
                        "style": str(item.style),
                        "title": "",
                        "x": item.x,
                        "y": item.y,
                    }
                    if is_extended:
                        item_dict["help_id"] = item.help_id
                    try:
                        item_dict["title"] = str(item.title)
                        if item_dict["title"] != "":
                            res.add_tag("file.string.extracted", item_dict["title"])
                    except UnicodeDecodeError:
                        if corrupted_dialog_section is None:
                            heur = Heuristic(13)
                            corrupted_dialog_section = ResultSection(heur.name, heuristic=heur, parent=res)
                        if "title" in dialog_dict and dialog_dict["title"]:
                            corrupted_dialog_section.add_line(
                                f"Can't decode title of dialog item from dialog named {dialog.title}"
                            )
                        else:
                            corrupted_dialog_section.add_line("Can't decode title of dialog item")
                    dialog_dict["items"].append(item_dict)
                dialogs_list.append(dialog_dict)

            self.features["resources_manager"]["dialogs"] = dialogs_list

        if resources_manager.has_html:
            try:
                self.features["resources_manager"]["html"] = resources_manager.html
            except UnicodeDecodeError:
                heur = Heuristic(13)
                heur_section = ResultSection(heur.name, heuristic=heur)
                heur_section.add_line("Can't decode html object from resources manager")
                res.add_subsection(heur_section)
                # Do our best to find resource 0x17 (23) and save it in the features

                def fetch_last_content(resource):
                    if len(resource.childs) == 1:
                        return fetch_last_content(resource.childs[0])
                    elif len(resource.childs) == 0:
                        return resource.content

                for resource in self.binary.resources.childs:
                    if resource.id == 0x17:
                        content = fetch_last_content(resource)
                        if content is not None:
                            self.features["resources_manager"]["html"] = bytearray(content).decode(
                                "utf-8", "backslashreplace"
                            )

        if resources_manager.has_icons:
            sub_res = ResultMultiSection("Icons")
            sub_res_table = TableSectionBody()
            sub_res_image = ImageSectionBody(self.request)
            manager_icons = list(resources_manager.icons)
            if not manager_icons and group_icon_data_missing(self.binary):
                # The manager found icons (has_icons) but the RT_GROUP_ICON data nodes were
                # dropped by the parser, so it could not associate any icon with a group entry.
                # Rebuild them from the RT_ICON tree leaves so they still get extracted.
                manager_icons = icons_from_resource_tree(self.binary)
            icons = []
            unshowable_icons = []
            for idx, icon in enumerate(manager_icons):
                try:
                    icon_lang = lief.PE.RESOURCE_LANGS(icon.lang).name
                except ValueError:
                    icon_lang = "???"
                icons.append(
                    {
                        "icon_id": icon.id,
                        # "pixels": icon.pixels,
                        "planes": icon.planes,
                        "height": icon.height,
                        "width": icon.width,
                        "lang": icon_lang,
                        "sublang": sublang_pair_name(icon.lang, icon.sublang),
                        # TODO: Add hash as a structure with values similar to the authentihash
                        # "hash": {"sha256": hashlib.sha256(bytearray(icon.pixels)).hexdigest()},
                    }
                )
                sub_res_table.add_row(
                    TableRow(
                        **{
                            "ID": icon.id,
                            "Lang": icon_lang,
                            "Size": f"{icon.height}x{icon.width}",
                            "Size (bytes)": len(icon.pixels),
                            "Saved as": f"icon_{idx}.ico",
                        }
                    )
                )
                temp_path = os.path.join(self.working_directory, f"icon_{idx}.ico")
                icon.save(temp_path)
                try:
                    sub_res_image.add_image(temp_path, f"icon_{idx}.ico", f"Icon {idx} extracted from the PE file")
                except (OSError, ValueError):
                    unshowable_icons.append(f"icon_{idx}.ico")
                    self.request.add_supplementary(
                        temp_path,
                        f"icon_{idx}.ico",
                        f"Icon {idx} extracted from the PE file",
                        parent_relation=PARENT_RELATION.EXTRACTED,
                    )
                except Image.DecompressionBombError:
                    heur = Heuristic(28)
                    heur_section = ResultSection(heur.name, heuristic=heur)
                    heur_section.add_line(f"icon_{idx}.ico")
                    sub_res.add_subsection(heur_section)

                    unshowable_icons.append(f"icon_{idx}.ico")
                    self.request.add_supplementary(
                        temp_path,
                        f"icon_{idx}.ico",
                        f"Icon {idx} extracted from the PE file",
                        parent_relation=PARENT_RELATION.EXTRACTED,
                    )

            self.features["resources_manager"]["icons"] = icons
            sub_res.add_section_part(sub_res_table)
            sub_res.add_section_part(sub_res_image)
            if unshowable_icons:
                heur = Heuristic(27)
                heur_section = ResultSection(heur.name, heuristic=heur)
                heur_section.add_lines(unshowable_icons)
                sub_res.add_subsection(heur_section)
            res.add_subsection(sub_res)

        if resources_manager.has_manifest:
            manifest = resources_manager.manifest
            if isinstance(manifest, str):
                self.features["resources_manager"]["manifest"] = manifest
            elif isinstance(manifest, bytes):
                self.features["resources_manager"]["manifest"] = manifest.decode("utf-8", "backslashreplace")
            else:
                heur = Heuristic(13)
                heur_section = ResultSection(heur.name, heuristic=heur)
                heur_section.add_line("Found corrupted manifest")
                res.add_subsection(heur_section)

        if resources_manager.has_string_table:
            self.features["resources_manager"]["string_table"] = []
            for string_table in resources_manager.string_table:
                try:
                    self.features["resources_manager"]["string_table"].append(str(string_table))
                except UnicodeDecodeError:
                    self.features["resources_manager"]["string_table"].append("AL_PE: UnicodeDecodeError")

        if resources_manager.has_version:
            sub_res = ResultOrderedKeyValueSection("Version")
            try:
                versions = resources_manager.version
                if isinstance(versions, lief.lief_errors):
                    raise ValueError(versions)

                if len(versions) > 1:
                    # Usually one version resource per language leaf (MUI binaries); every string
                    # table is merged below so no language's strings are lost
                    ResultSection(f"Multiple ({len(versions)}) version resources found", parent=sub_res)

                    def version_language_priority(version):
                        # Prefer English then French version resources for the reported values,
                        # keeping the resource order as tie-breaker.
                        langs = set()
                        if version.string_file_info is not None:
                            for string_table in version.string_file_info.children:
                                try:
                                    langs.add(int(string_table.key[:4], 16) & 0x3FF)
                                except ValueError:
                                    pass
                        if lief.PE.RESOURCE_LANGS.ENGLISH.value in langs:
                            return 0
                        if lief.PE.RESOURCE_LANGS.FRENCH.value in langs:
                            return 1
                        return 2

                    versions = sorted(versions, key=version_language_priority)

                self.features["resources_manager"]["version"] = {"type": versions[0].type}
                sub_res.add_item("Type", versions[0].type)

                def fixed_file_info_dict(fixed_file_info):
                    fixed_file_info_t = lief.PE.ResourceVersion.fixed_file_info_t
                    try:
                        file_os = fixed_file_info_t.VERSION_OS(fixed_file_info.file_os).name
                    except ValueError:
                        file_os = str(fixed_file_info.file_os)
                    try:
                        # FILE_TYPE_DETAILS values combine file_type and file_subtype to disambiguate
                        # driver from font subtypes; file_type_details does that combination for us.
                        # On an invalid subtype, nanobind emits a RuntimeWarning on top of the
                        # ValueError we handle, so silence it to keep it out of the service logs.
                        with warnings.catch_warnings():
                            warnings.simplefilter("ignore", RuntimeWarning)
                            file_subtype = fixed_file_info.file_type_details.name
                    except (ValueError, AttributeError):
                        file_subtype = str(fixed_file_info.file_subtype)
                    try:
                        file_type = fixed_file_info_t.FILE_TYPE(fixed_file_info.file_type).name
                    except ValueError:
                        file_type = str(fixed_file_info.file_type)
                    return {
                        "file_date_ls": fixed_file_info.file_date_ls,
                        "file_date_ms": fixed_file_info.file_date_ms,
                        "file_flags": fixed_file_info.file_flags,
                        "file_flags_mask": fixed_file_info.file_flags_mask,
                        "file_os": file_os,
                        "file_subtype": file_subtype,
                        "file_type": file_type,
                        "file_version_ls": fixed_file_info.file_version_ls,
                        "file_version_ms": fixed_file_info.file_version_ms,
                        "product_version_ls": fixed_file_info.product_version_ls,
                        "product_version_ms": fixed_file_info.product_version_ms,
                        "signature": fixed_file_info.signature,
                        "struct_version": fixed_file_info.struct_version,
                    }

                fixed_file_infos = [v.file_info for v in versions if v.file_info is not None]
                if fixed_file_infos:
                    # The first fixed file info is the reported one; the others should be identical
                    # copies, so any difference between them is worth showing
                    ffi_dict = fixed_file_info_dict(fixed_file_infos[0])
                    self.features["resources_manager"]["version"]["fixed_file_info"] = ffi_dict
                    sub_sub_res = ResultOrderedKeyValueSection("fixed_file_info")
                    sub_sub_res.add_item("file_date_LS", ffi_dict["file_date_ls"])
                    sub_sub_res.add_item("file_date_MS", ffi_dict["file_date_ms"])
                    sub_sub_res.add_item("file_flags", ffi_dict["file_flags"])
                    sub_sub_res.add_item("file_flags_mask", ffi_dict["file_flags_mask"])
                    sub_sub_res.add_item("file_os", ffi_dict["file_os"])
                    sub_sub_res.add_item("file_subtype", ffi_dict["file_subtype"])
                    sub_sub_res.add_item("file_type", ffi_dict["file_type"])
                    sub_sub_res.add_item("file_version_LS", ffi_dict["file_version_ls"])
                    sub_sub_res.add_item("file_version_MS", ffi_dict["file_version_ms"])
                    sub_sub_res.add_item("product_version_LS", ffi_dict["product_version_ls"])
                    sub_sub_res.add_item("product_version_MS", ffi_dict["product_version_ms"])
                    sub_sub_res.add_item("signature", ffi_dict["signature"])
                    sub_sub_res.add_item("struct_version", ffi_dict["struct_version"])
                    conflict_section = None
                    for index, other in enumerate(fixed_file_infos[1:], start=2):
                        differing = {k: v for k, v in fixed_file_info_dict(other).items() if v != ffi_dict[k]}
                        if differing:
                            if conflict_section is None:
                                conflict_section = ResultSection(
                                    "Conflicting fixed_file_info between version resources",
                                    parent=sub_sub_res,
                                )
                            for k, v in sorted(differing.items()):
                                conflict_section.add_line(
                                    f"Version resource {index} {k}: {v} (reported: {ffi_dict[k]})"
                                )
                    sub_res.add_subsection(sub_sub_res)

                string_file_infos = [v.string_file_info for v in versions if v.string_file_info is not None]
                if string_file_infos:
                    self.features["resources_manager"]["version"]["string_file_info"] = {
                        "key": string_file_infos[0].key,
                        "type": string_file_infos[0].type,
                        "langcode_items": [],
                    }
                    sub_sub_res = ResultOrderedKeyValueSection("string_file_info")
                    sub_sub_res.add_item("key", string_file_infos[0].key)
                    sub_sub_res.add_item("type", string_file_infos[0].type)
                    # Merge the string tables of every version resource, skipping exact duplicates
                    seen_tables = {}
                    item_index = 0
                    string_tables = [
                        string_table
                        for string_file_info in string_file_infos
                        for string_table in string_file_info.children
                    ]
                    for string_table in string_tables:
                        table_signature = (
                            string_table.key,
                            tuple(sorted((entry.key, entry.value) for entry in string_table.entries)),
                        )
                        if table_signature in seen_tables:
                            seen_tables[table_signature] += 1
                            continue
                        seen_tables[table_signature] = 1
                        item_index += 1
                        sub_sub_sub_res = ResultOrderedKeyValueSection(f"langcode_items {item_index}")
                        sub_sub_sub_res.add_item("key", string_table.key)
                        sub_sub_sub_res.add_item("type", string_table.type)
                        langcodeitem_dict = {
                            "key": string_table.key,
                            "type": string_table.type,
                            "lang": None,
                            "sublang": None,
                            "code_page": None,
                            "items": {},
                        }
                        # The string table key packs the language identifier and code page as two 4-digit
                        # hex numbers (e.g. 040904b0), which LIEF used to decode on our behalf
                        try:
                            lang_id = int(string_table.key[:4], 16)
                            code_page = int(string_table.key[4:8], 16)
                            lang = lief.PE.RESOURCE_LANGS(lang_id & 0x3FF).name
                            sublang = sublang_name(lang_id)
                            langcodeitem_dict["lang"] = lang
                            sub_sub_sub_res.add_item("lang", lang)
                            # This language is declared inside the version data, independently from the
                            # resource tree language that the get_node_data walk collects, so it can
                            # genuinely differ from (and complements) the tree-based collection.
                            # Deduplicated and sorted after the tree walk in get_node_data.
                            self.features["resources_manager"]["langs_available"].append(lang)
                            langcodeitem_dict["sublang"] = sublang
                            sub_sub_sub_res.add_item("sublang", sublang)
                            self.features["resources_manager"]["sublangs_available"].append(sublang)
                            langcodeitem_dict["code_page"] = CODE_PAGES.get(code_page, str(code_page))
                            sub_sub_sub_res.add_item("code_page", langcodeitem_dict["code_page"])
                        except ValueError:
                            sub_sub_sub_res.set_heuristic(13)
                            del langcodeitem_dict["lang"]
                            del langcodeitem_dict["sublang"]
                            del langcodeitem_dict["code_page"]

                        sub_sub_sub_sub_res = ResultOrderedKeyValueSection("items")
                        for entry in sorted(string_table.entries, key=lambda e: e.key):
                            langcodeitem_dict["items"][entry.key] = entry.value
                            sub_sub_sub_sub_res.add_item(entry.key, entry.value)
                            if entry.key == "OriginalFilename":
                                sub_sub_res.add_tag("file.pe.versions.filename", entry.value)
                            elif entry.key == "FileDescription":
                                sub_sub_res.add_tag("file.pe.versions.description", entry.value)
                        self.features["resources_manager"]["version"]["string_file_info"]["langcode_items"].append(
                            langcodeitem_dict
                        )
                        sub_sub_sub_res.add_subsection(sub_sub_sub_sub_res)
                        sub_sub_res.add_subsection(sub_sub_sub_res)
                    duplicated_tables = {sig[0]: count for sig, count in seen_tables.items() if count > 1}
                    if duplicated_tables:
                        duplicate_section = ResultSection("Duplicated string tables", parent=sub_sub_res)
                        for table_key, count in sorted(duplicated_tables.items()):
                            duplicate_section.add_line(f"String table {table_key} was seen {count} times")
                    sub_res.add_subsection(sub_sub_res)

                var_file_infos = [v.var_file_info for v in versions if v.var_file_info is not None]
                if var_file_infos:
                    # Merge translations of every version resource, keeping their order without duplicates
                    translations = list(
                        dict.fromkeys(
                            value
                            for var_file_info in var_file_infos
                            for var in var_file_info.vars
                            for value in var.values
                        )
                    )
                    self.features["resources_manager"]["version"]["var_file_info"] = {
                        "key": var_file_infos[0].key,
                        "type": var_file_infos[0].type,
                        "translations": translations,
                    }
                    sub_sub_res = ResultOrderedKeyValueSection("var_file_info")
                    sub_sub_res.add_item("key", var_file_infos[0].key)
                    sub_sub_res.add_item("type", var_file_infos[0].type)
                    sub_sub_res.add_item("translations", ", ".join(map(str, translations)))
                    sub_res.add_subsection(sub_sub_res)
            except (ValueError, IndexError):
                sub_res.set_heuristic(13)
            res.add_subsection(sub_res)

        if resources_manager.has_type(resources_manager.TYPE.RCDATA):

            def recurse_rc_data(node, name):
                if node.has_name:
                    name = node.name
                if node.is_directory:
                    for sub_node in node.childs:
                        recurse_rc_data(sub_node, name)
                else:
                    content = node.content.tobytes()
                    if len(content) <= 100:
                        return
                    with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as fh:
                        rc_data_file = fh.name
                        fh.write(content)

                    rc_data_type = self.identify.fileinfo(rc_data_file, generate_hashes=False)["type"]
                    if rc_data_type == "unknown":
                        return
                    if not any(rc_data_type.startswith(x) for x in ["text/", "resource/"]):
                        self.request.add_extracted(
                            rc_data_file,
                            name or f"rc_data_{node.offset}",
                            "Extracted from binary's RT_RCDATA resources",
                        )
                    else:
                        self.request.add_supplementary(
                            rc_data_file,
                            name or f"rc_data_{node.offset}",
                            "Extracted from binary's RT_RCDATA resources",
                        )

            recurse_rc_data(resources_manager.get_node_type(resources_manager.TYPE.RCDATA), "")

        sub_res = ResultTableSection("Summary")
        current_resource_type = ""

        def get_node_data(node):
            data = {}
            if isinstance(node, lief.PE.ResourceDirectory):
                data["characteristics"] = node.characteristics
                data["num_childs"] = len(node.childs)
                data["depth"] = node.depth
                if node.has_name:
                    data["name"] = node.name
                    res.add_tag("file.pe.resources.name", node.name)
                data["resource_id"] = node.id
                if node.depth == 1:
                    try:
                        data["resource_type"] = resources_manager.TYPE(node.id).name
                    except ValueError:
                        data["resource_type"] = "???"
                    nonlocal current_resource_type
                    current_resource_type = data["resource_type"]
                    if current_resource_type == "???" and node.has_name:
                        current_resource_type = node.name
                data["is_data"] = node.is_data
                data["is_directory"] = node.is_directory
                data["major_version"] = node.major_version
                data["minor_version"] = node.minor_version
                data["numberof_id_entries"] = node.numberof_id_entries
                data["numberof_name_entries"] = node.numberof_name_entries
                data["time_date_stamp"] = node.time_date_stamp
                if data["num_childs"] > 0:
                    data["childs"] = []
                    for child in node.childs:
                        data["childs"].append(get_node_data(child))
            elif isinstance(node, lief.PE.ResourceData):
                # We could go deeper and figure out which type of resource it is, to get more information.
                data["num_childs"] = len(node.childs)
                data["code_page"] = node.code_page
                # data["content"] = node.content
                resource_data = bytearray(node.content)
                entropy = calculate_partition_entropy(BytesIO(resource_data))[0]
                resource_sha256 = hashlib.sha256(resource_data).hexdigest()
                data["sha256"] = resource_sha256
                data["entropy"] = entropy
                sub_res.add_row(
                    TableRow(**{"SHA256": resource_sha256, "Type": current_resource_type, "Entropy": entropy})
                )
                data["depth"] = node.depth
                if node.has_name:
                    data["name"] = node.name
                    res.add_tag("file.pe.resources.name", node.name)
                data["resource_id"] = node.id
                data["is_data"] = node.is_data
                data["is_directory"] = node.is_directory
                data["offset"] = node.offset
                data["reserved"] = node.reserved
                # In the PE resource layout (type -> name/id -> language), the ID of a depth-3 data
                # entry is its language identifier. Collecting it here covers every resource type,
                # instead of only the ones the ResourcesManager helpers expose (icons, version, ...).
                if node.depth == 3 and not node.has_name:
                    try:
                        self.features["resources_manager"]["langs_available"].append(
                            lief.PE.RESOURCE_LANGS(node.id & 0x3FF).name
                        )
                    except ValueError:
                        self.features["resources_manager"]["langs_available"].append("???")
                    self.features["resources_manager"]["sublangs_available"].append(sublang_name(node.id))
            else:
                raise Exception("Binary with unknown ResourceNode")

            return data

        self.features["resources"] = get_node_data(self.binary.resources)
        self.features["resources_manager"]["langs_available"] = sorted(
            set(self.features["resources_manager"]["langs_available"])
        )
        self.features["resources_manager"]["sublangs_available"] = sorted(
            set(self.features["resources_manager"]["sublangs_available"])
        )
        res.add_subsection(sub_res)

        res.add_item("Languages", ", ".join(self.features["resources_manager"]["langs_available"]))
        for lang in self.features["resources_manager"]["langs_available"]:
            res.add_tag("file.pe.resources.language", lang)
        res.add_item("Sublanguages", ", ".join(self.features["resources_manager"]["sublangs_available"]))

        if not self.features["resources_manager"]["langs_available"]:
            heur = Heuristic(36)
            ResultSection(heur.name, heuristic=heur, parent=self.file_res)

        self.file_res.add_section(res)

    def add_signatures(self):
        self.features["verify_signature"] = self.binary.verify_signature().name

        if not self.binary.has_signatures:
            return

        all_certs = [
            lief.PE.x509.parse(f"{trusted_certs_path}{x}")
            for trusted_certs_path in self.config.get("trusted_certs", [])
            for x in os.listdir(trusted_certs_path)
        ]
        trusted_certs = [item for sublist in all_certs for item in sublist]

        res = ResultSection("Signatures")

        self.features["signatures"] = []
        signature_res = []
        expired_signers = []
        untrusted_signers = []
        for signature_index, signature in enumerate(self.binary.signatures):
            extra_certs = []

            def recurse_cert(issuer):
                # find_crt_subject only accepts str: a bytes issuer (non-UTF-8 x509 name) can't
                # be looked up, so treat it like an unresolvable issuer and stop the chain there
                if issuer is None or isinstance(issuer, bytes):
                    return
                issuer_cert = signature.find_crt_subject(issuer)
                if issuer_cert is None or issuer_cert.subject == issuer_cert.issuer:
                    return
                recurse_cert(issuer_cert.issuer)
                if issuer_cert.is_trusted_by(trusted_certs + extra_certs) == lief.PE.x509.VERIFICATION_FLAGS.OK:
                    extra_certs.append(issuer_cert)

            signature_dict = {
                "version": signature.version,
                "algorithm": get_lief_enum_name(signature.digest_algorithm),
                "signers": [],
                "certificates": [],
                "content_info": {
                    "algorithm": signature.content_info.digest_algorithm.name,
                    "digest": signature.content_info.digest.hex(),
                    "content_type": signature.content_info.content_type,
                },
                "check": signature.check().name,
            }

            sub_res = ResultOrderedKeyValueSection(f"Signature - {signature_index + 1}")
            sub_res.add_item("Version", signature.version)
            sub_res.add_item("Algorithm", signature.digest_algorithm.name.replace("_", ""))
            sub_res.add_item("Content Info Algorithm", signature.content_info.digest_algorithm.name.replace("_", ""))
            sub_res.add_item("Content Info Digest", signature_dict["content_info"]["digest"])
            sub_res.add_item("Content Info Content Type", signature.content_info.content_type)
            for signer_index, signer in enumerate(signature.signers):
                sub_sub_res = ResultOrderedKeyValueSection(f"Signer - {signer_index + 1}")
                signer_dict = {
                    "version": signer.version,
                    "issuer": bytes_to_backslashreplace_utf8_str(signer.issuer),
                    "serial_number": signer.serial_number.hex(),
                    "encryption_algorithm": get_lief_enum_name(signer.encryption_algorithm),
                    "digest_algorithm": get_lief_enum_name(signer.digest_algorithm),
                    "encrypted_digest": signer.encrypted_digest.hex(),
                    "cert": None,
                    "authenticated_attributes": [
                        # We could keep parsing each type of attribute
                        get_lief_enum_name(attribute.type)
                        for attribute in signer.authenticated_attributes
                    ],
                    "unauthenticated_attributes": [
                        # We could keep parsing each type of attribute
                        get_lief_enum_name(attribute.type)
                        for attribute in signer.unauthenticated_attributes
                    ],
                }
                sub_sub_res.add_item("Version", signer.version)
                sub_sub_res.add_item("Digest Algorithm", signer.digest_algorithm.name.replace("_", ""))
                sub_sub_res.add_item("Authenticated Attributes", ", ".join(signer_dict["authenticated_attributes"]))
                sub_sub_res.add_item("Unauthenticated Attributes", ", ".join(signer_dict["unauthenticated_attributes"]))
                opus_info = [x for x in signer.authenticated_attributes if x.type == x.TYPE.SPC_SP_OPUS_INFO]
                if opus_info and opus_info[0].program_name:
                    opus_info_res = ResultOrderedKeyValueSection("SPC_SP_OPUS_INFO attribute", parent=sub_sub_res)
                    opus_info_res.add_item("Program Name", opus_info[0].program_name)
                    opus_info_res.add_tag(
                        "file.pe.authenticode.spc_sp_opus_info.program_name", opus_info[0].program_name
                    )

                if signer.cert is not None and signer.cert.issuer is not None:
                    recurse_cert(signer.cert.issuer)
                    extracted_cert_info = extract_cert_info(signer.cert, trusted_certs + extra_certs)
                    signer_dict["cert"] = extracted_cert_info
                    if "BADCERT_EXPIRED" in extracted_cert_info["is_trusted"]:
                        expired_signers.append((signer_index + 1, signer.serial_number.hex()))
                    elif extracted_cert_info["is_trusted"] != "OK":
                        untrusted_signers.append((signer_index + 1, signer.serial_number.hex()))

                    sub_sub_sub_res = ResultOrderedKeyValueSection("Signer Certificate")
                    sub_sub_sub_res.add_item("Version", extracted_cert_info["version"])
                    sub_sub_sub_res.add_item("Subject", extracted_cert_info["subject"])
                    sub_sub_sub_res.add_tag("cert.subject", extracted_cert_info["subject"])
                    if extracted_cert_info["subject"] == (
                        "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, "
                        "CN=Microsoft Windows Hardware Compatibility Publisher"
                    ):
                        subject_WHQL = ResultSection("Signer Subject", parent=sub_sub_sub_res)
                        subject_WHQL.add_line(
                            (
                                "Common subject for Windows Hardware Compatibility driver signing, may be "
                                "used by Attestation Signed Malware."
                            )
                        )
                    sub_sub_sub_res.add_item("Issuer", extracted_cert_info["issuer"])
                    sub_sub_sub_res.add_tag("cert.issuer", extracted_cert_info["issuer"])
                    sub_sub_sub_res.add_item("Serial Number", extracted_cert_info["serial_number"])
                    sub_sub_sub_res.add_tag("cert.serial_no", extracted_cert_info["serial_number"])
                    sub_sub_sub_res.add_item(
                        "Valid From", datetime.datetime(*extracted_cert_info["valid_from"]).isoformat()
                    )
                    sub_sub_sub_res.add_tag(
                        "cert.valid.start", datetime.datetime(*extracted_cert_info["valid_from"]).isoformat()
                    )
                    sub_sub_sub_res.add_item(
                        "Valid To", datetime.datetime(*extracted_cert_info["valid_to"]).isoformat()
                    )
                    sub_sub_sub_res.add_tag(
                        "cert.valid.end", datetime.datetime(*extracted_cert_info["valid_to"]).isoformat()
                    )
                    signer_raw_hex = bytes.fromhex(extracted_cert_info["raw_hex"])
                    # The sha1 thumbprint generated this way match what VirusTotal reports for 'certificate thumbprints'
                    sha1_hex = hashlib.sha1(signer_raw_hex).hexdigest()
                    sha256_hex = hashlib.sha256(signer_raw_hex).hexdigest()
                    md5_hex = hashlib.md5(signer_raw_hex).hexdigest()
                    sub_sub_sub_res.add_tag("cert.thumbprint", sha1_hex)
                    sub_sub_sub_res.add_tag("cert.thumbprint", sha256_hex)
                    sub_sub_sub_res.add_tag("cert.thumbprint", md5_hex)

                    if extracted_cert_info["is_trusted"] != "OK":
                        sub_sub_sub_res.add_item("Verification", extracted_cert_info["is_trusted"])

                    cscb_results = lookup_signer_family(
                        self.cscb, -1, sha1_hex, sha256_hex, md5_hex, extracted_cert_info["serial_number"]
                    )
                    certcentral_results = lookup_signer_family(
                        self.certcentral,
                        self.certcentral_reason_index,
                        sha1_hex,
                        sha256_hex,
                        md5_hex,
                        extracted_cert_info["serial_number"],
                    )
                    if cscb_results or certcentral_results:
                        heur = Heuristic(29)
                        heur_section = ResultTableSection(heur.name, heuristic=heur)
                        for element in cscb_results:
                            heur_section.add_row(
                                TableRow(
                                    {"Type": element[0], "Value": element[1], "Family": element[2], "Source": "CSCB"}
                                )
                            )
                            heur_section.add_tag("attribution.family", element[2])
                        for element in certcentral_results:
                            heur_section.add_row(
                                TableRow(
                                    {
                                        "Type": element[0],
                                        "Value": element[1],
                                        "Family": element[2],
                                        "Source": "CertCentral",
                                    }
                                )
                            )
                            heur_section.add_tag("attribution.family", element[2])
                        sub_sub_sub_res.add_subsection(heur_section)

                    sub_sub_res.add_subsection(sub_sub_sub_res)
                else:
                    heur = Heuristic(13)
                    heur_section = ResultSection(heur.name, heuristic=heur)
                    heur_section.add_line("Signer certificate or signer certificate's issuer is non-existant")
                    sub_sub_res.add_subsection(heur_section)
                    del signer_dict["cert"]

                signature_dict["signers"].append(signer_dict)
                sub_res.add_subsection(sub_sub_res)
            for certificate_index, certificate in enumerate(signature.certificates):
                if certificate.is_trusted_by(trusted_certs + extra_certs) != lief.PE.x509.VERIFICATION_FLAGS.OK:
                    recurse_cert(certificate.issuer)
                extracted_cert_info = extract_cert_info(certificate, trusted_certs + extra_certs)
                signature_dict["certificates"].append(extracted_cert_info)
                sub_sub_res = ResultOrderedKeyValueSection(f"Certificate - {certificate_index + 1}")
                sub_sub_res.add_item("Version", extracted_cert_info["version"])
                sub_sub_res.add_item("Subject", extracted_cert_info["subject"])
                sub_sub_res.add_item("Issuer", extracted_cert_info["issuer"])
                raw_cert = bytes.fromhex(extracted_cert_info["raw_hex"])
                file_name = f"certificate.{signature_index + 1}.{certificate_index + 1}"
                temp_path = os.path.join(self.working_directory, file_name)
                with open(temp_path, "wb") as myfile:
                    myfile.write(raw_cert)
                self.request.add_supplementary(
                    temp_path,
                    file_name,
                    f"{file_name} extracted from binary's resources",
                    parent_relation=PARENT_RELATION.EXTRACTED,
                )
                sub_sub_res.add_item("SHA1", hashlib.sha1(raw_cert).hexdigest())
                sub_sub_res.add_item("SHA256", hashlib.sha256(raw_cert).hexdigest())
                sub_sub_res.add_item("MD5", hashlib.md5(raw_cert).hexdigest())
                sub_sub_res.add_item("Serial Number", extracted_cert_info["serial_number"])
                sub_sub_res.add_item("Valid From", datetime.datetime(*extracted_cert_info["valid_from"]).isoformat())
                sub_sub_res.add_item("Valid To", datetime.datetime(*extracted_cert_info["valid_to"]).isoformat())
                sub_res.add_subsection(sub_sub_res)

            self.features["signatures"].append(signature_dict)

            if (
                signature.content_info.digest_algorithm.name.replace("_", "").lower()
                not in self.features["authentihash"]
            ):
                heur = Heuristic(1)
                heur_section = ResultMultiSection(heur.name, heuristic=heur)
                heur_text_body = TextSectionBody()
                heur_text_body.add_line("The signature hash does not exist in the program data")
                heur_section.add_section_part(heur_text_body)
                heur_kv_body = OrderedKVSectionBody()
                heur_kv_body.add_item(
                    "Signature hash", signature.content_info.digest_algorithm.name.replace("_", "").lower()
                )
                heur_kv_body.add_item("Program data hashes", ", ".join(self.features["authentihash"].keys()))
                heur_section.add_section_part(heur_kv_body)
                sub_res.add_subsection(heur_section)
            elif (
                signature.content_info.digest.hex()
                != self.features["authentihash"][signature.content_info.digest_algorithm.name.replace("_", "").lower()]
            ):
                heur = Heuristic(1)
                heur_section = ResultMultiSection(heur.name, heuristic=heur)
                heur_text_body = TextSectionBody()
                heur_text_body.add_line(
                    (
                        "The signature does not match the authentihash data found "
                        f"for {signature.content_info.digest_algorithm.name.replace('_', '').lower()}"
                    )
                )
                heur_section.add_section_part(heur_text_body)
                heur_kv_body = OrderedKVSectionBody()
                heur_kv_body.add_item("Signature", signature.content_info.digest.hex())
                heur_kv_body.add_item(
                    "Authentihash data",
                    self.features["authentihash"][
                        signature.content_info.digest_algorithm.name.replace("_", "").lower()
                    ],
                )
                heur_section.add_section_part(heur_kv_body)
                sub_res.add_subsection(heur_section)

            # Supported by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383/pe.py#L898
            if len(signature.certificates) < 2:
                heur = Heuristic(8)
                heur_section = ResultSection(heur.name, heuristic=heur)
                heur_section.add_line(
                    f"This is probably an error. Less than two certificates were found : {len(signature.certificates)}"
                )
                sub_res.add_subsection(heur_section)
                signature_res.append(sub_res)
                continue

            denied_algorithm = []
            self_signed_signer = []
            for signer in signature.signers:
                if signer.encryption_algorithm.name not in ACCEPTED_ALGORITHMS:
                    denied_algorithm.append(signer.encryption_algorithm.name)
                # TODO Do not re-parse it again.
                if signer.cert is not None:
                    extracted_cert_info = extract_cert_info(signer.cert, trusted_certs + extra_certs)
                    if (
                        extracted_cert_info["issuer"] == extracted_cert_info["subject"]
                        and extracted_cert_info["is_trusted"] != "OK"
                    ):
                        self_signed_signer.append(extracted_cert_info["issuer"])
                        break

            if denied_algorithm:
                heur = Heuristic(9)
                heur_section = ResultOrderedKeyValueSection(heur.name, heuristic=heur)
                heur_section.add_item("Offending algorithms", ", ".join(denied_algorithm))
                heur_section.add_tag("attribution.exploit", "CVE_2020_0601")
                sub_res.add_subsection(heur_section)

            if self_signed_signer:
                heur = Heuristic(6)
                heur_section = ResultOrderedKeyValueSection(heur.name, heuristic=heur)
                heur_section.add_item("Subject/Issuer", self_signed_signer[0])
                sub_res.add_subsection(heur_section)

            if denied_algorithm or self_signed_signer:
                signature_res.append(sub_res)
                continue

            first_issuer = signature.certificates[0].issuer
            all_same_issuer = True
            for cert in signature.certificates:
                if cert.issuer != first_issuer:
                    all_same_issuer = False
                    break
            if all_same_issuer:
                heur = Heuristic(3)
                heur_section = ResultMultiSection(heur.name, heuristic=heur)
                heur_text_body = TextSectionBody()
                heur_text_body.add_line("All issuers matching is usually a sign of it being self-signed")
                heur_section.add_section_part(heur_text_body)
                heur_kv_body = OrderedKVSectionBody()
                heur_kv_body.add_item("Issuer", bytes_to_backslashreplace_utf8_str(first_issuer))
                heur_section.add_section_part(heur_kv_body)
                sub_res.add_subsection(heur_section)
                signature_res.append(sub_res)
                continue

            if signature_dict["check"] != "OK":
                heur = Heuristic(5)
                heur_section = ResultSection(heur.name, heuristic=heur)
                heur_section.add_lines(
                    [
                        "Possibly self signed.",
                        (
                            "Could not identify a chain of trust back to a known root CA, but certificates "
                            "presented were issued by different issuers"
                        ),
                    ]
                )
                sub_res.add_subsection(heur_section)
            signature_res.append(sub_res)

        if "INVALID_SIGNER" in self.features["verify_signature"]:
            heur = Heuristic(10)
            heur_section = ResultSection(heur.name, heuristic=heur)
            heur_section.add_line(
                f"INVALID_SIGNER found while verifying signature : {self.features['verify_signature']}"
            )
            res.add_subsection(heur_section)

        if not expired_signers and not untrusted_signers and self.features["verify_signature"] == "OK":
            heur = Heuristic(2)
            heur_section = ResultSection(heur.name, heuristic=heur)
            heur_section.add_line(f"OK found while verifying signature : {self.features['verify_signature']}")
            res.add_subsection(heur_section)

        if untrusted_signers:
            untrusted_section = ResultSection(f"Untrusted signer{'s' if len(untrusted_signers) > 1 else ''} found")
            untrusted_section.add_tag("file.behavior", "PE with Untrusted Signer")
            for signer_index, signer_serial in untrusted_signers:
                untrusted_section.add_line(f"Signer {signer_index} ({signer_serial}) is untrusted.")
            res.add_subsection(untrusted_section)

        if expired_signers:
            expired_section = ResultSection(f"Expired signer{'s' if len(expired_signers) > 1 else ''} found")
            expired_section.add_tag("file.behavior", "PE with Expired Signer")
            for signer_index, signer_serial in expired_signers:
                expired_section.add_line(f"Signer {signer_index} ({signer_serial}) is expired.")
            res.add_subsection(expired_section)

        for sig_res in signature_res:
            res.add_subsection(sig_res)

        self.file_res.add_section(res)

    def add_overlay(self):
        if (
            self.features["size"] <= self.config.get("overlay_analysis_file_max_size", 50000000)
            or self.request.deep_scan
        ):
            res = ResultMultiSection("Overlay", parent=self.file_res)
            overlay = bytearray(self.binary.overlay)
            entropy_data = calculate_partition_entropy(BytesIO(overlay))
            self.features["overlay"] = {"size": len(overlay), "entropy": entropy_data[0]}
            overlay_kv_section = OrderedKVSectionBody()
            overlay_kv_section.add_item("Size", self.features["overlay"]["size"])
            res.add_section_part(overlay_kv_section)
            if self.features["overlay"]["size"] > 0:
                if self.features["overlay"]["size"] > self.config.get(
                    "heur25_min_overlay_size", 31457280
                ) and self.features["overlay"]["entropy"] < self.config.get("heur25_min_overlay_entropy", 0.5):
                    heur = Heuristic(25)
                    heur_section = ResultSection(heur.name, heuristic=heur, parent=res)
                    heur_section.add_line(f"Overlay Size: {self.features['overlay']['size']}")
                    heur_section.add_line(f"Overlay Entropy: {self.features['overlay']['entropy']}")

                    file_name = "pe_without_overlay"
                    temp_path = os.path.join(self.working_directory, file_name)
                    data_len = self.features["size"] - self.features["overlay"]["size"]
                    with open(self.request.file_path, "rb") as f:
                        data = bytearray(f.read(data_len))
                    with open(temp_path, "wb") as f:
                        f.write(data)
                    self.request.add_extracted(temp_path, file_name, f"{file_name} extracted from binary's resources")

                overlay_graph_section = GraphSectionBody()
                overlay_graph_section.set_colormap(
                    cmap_min=0, cmap_max=8, values=[round(x, 5) for x in entropy_data[1]]
                )
                res.add_section_part(overlay_graph_section)

                pe = self.binary
                overlays = {}
                while True:
                    try:
                        pe_array = bytearray(pe.overlay)
                        pe = lief.PE.parse(BytesIO(pe_array))
                        if pe is None:
                            break
                        pe_no_overlay = pe_array[: -len(pe.overlay)]
                        h = hashlib.sha256(pe_no_overlay).hexdigest()
                        if h not in overlays:
                            overlays[h] = (1, pe_array)
                        else:
                            overlays[h] = (overlays[h][0] + 1, pe_array)
                    except Exception:
                        break
                if len(overlays) > 1 or any(count > 1 for count, _ in overlays.values()):
                    stacked_overlays = ResultSection("Multiple PE stacked", parent=res)
                    for h, (count, data) in overlays.items():
                        stacked_overlays.add_line(f"{h} was seen {count} time{'s' if count > 1 else ''}")
                        file_name = f"{h}_overlay"
                        temp_path = os.path.join(self.working_directory, file_name)
                        with open(temp_path, "wb") as f:
                            f.write(data)
                        self.request.add_extracted(
                            temp_path,
                            file_name,
                            f"{file_name} extracted from binary's resources",
                            safelist_interface=self.api_interface,
                        )
                else:
                    file_name = "overlay"
                    temp_path = os.path.join(self.working_directory, file_name)
                    with open(temp_path, "wb") as f:
                        f.write(overlay)
                    self.request.add_extracted(
                        temp_path,
                        file_name,
                        f"{file_name} extracted from binary's resources",
                        safelist_interface=self.api_interface,
                    )

    def add_relocations(self):
        if not self.binary.has_relocations:
            heur = Heuristic(37)
            ResultSection(heur.name, heur.description, heuristic=heur, parent=self.file_res)
        if self.request.deep_scan and self.binary.has_relocations:
            self.features["relocations"] = [
                {
                    "virtual_address": relocation.virtual_address,
                    "entries": [
                        {
                            "address": entrie.address,
                            "data": entrie.data,
                            "position": entrie.position,
                            "size": entrie.size,
                            "type": get_lief_enum_name(entrie.type),
                        }
                        for entrie in relocation.entries
                    ],
                }
                for relocation in self.binary.relocations
            ]

    def _cleanup(self):
        self.binary = None
        self.features = None
        self.temp_res = None
        self.file_path = None
        super()._cleanup()

    def execute(self, request: ServiceRequest):
        request.result = Result()
        self.file_res = request.result
        self.request = request
        self.file_path = request.file_path

        lief_output_file = os.path.join(self.working_directory, "lief_output")
        lief.logging.set_path(lief_output_file)
        self.binary = lief.PE.parse(self.file_path)

        if self.binary is None:
            res = ResultSection("This file looks like a PE but failed loading.", heuristic=Heuristic(7))
            self.file_res.add_section(res)
            return

        try:
            if unmapper.is_mapped(self.binary, os.path.getsize(request.file_path)):
                in_data = pathlib.Path(request.file_path).read_bytes()
                out_data = unmapper.unmap(self.binary, in_data)
                if len(out_data) <= len(in_data) * 2:
                    file_name = f"{request.sha256}_unmapped"
                    temp_path = os.path.join(self.working_directory, file_name)
                    with open(temp_path, "wb") as f:
                        f.write(out_data)
                    self.request.add_extracted(
                        temp_path,
                        file_name,
                        f"{file_name} unmapped from binary",
                        safelist_interface=self.api_interface,
                    )
        except AttributeError:
            # Some PE are so corrupted they cause LIEF to not be able to recreate a new PE out of the modified bytes.
            # We will ignore those and keep going to make sure the rest is shown to the user.
            # The raised error is the following:
            # AttributeError: 'NoneType' object has no attribute 'remove_all_relocations'
            pass

        self.check_timestamps()
        self.check_exe_resources()
        self.check_dataless_resources()

        self.features = {}
        self.add_headers()
        self.add_sections()
        self.add_debug()
        self.add_exports()
        self.add_imports()
        self.add_configuration()
        self.add_resources()
        self.add_signatures()
        self.add_overlay()
        self.add_relocations()

        if os.path.exists(lief_output_file):
            lief_output = []
            with open(lief_output_file, "rb") as f:
                lief_output = f.readlines()

            lief_logging = {}
            lief_logging_stripped = defaultdict(list)
            for line in lief_output:
                if isinstance(line, bytes):
                    line = line.decode("utf-8", "backslashreplace")
                line = line.rstrip()
                if line.endswith(" (0x-2700)") or line.endswith(" (-0x2700)"):
                    line = line[:-10]
                line = line.rstrip("\x00")
                if not line:
                    continue
                if m := re.search("node id(:? \\d+)", line):
                    strip = m.group(1)
                    if strip.startswith(":"):
                        strip = strip[1:]
                    strip = strip.strip()
                    line = f"{line[: m.start(1)]}{line[m.end(1) :]}"
                    lief_logging_stripped[line].append(strip)
                if line in lief_logging:
                    lief_logging[line] += 1
                else:
                    lief_logging[line] = 1

            if lief_logging:
                res = ResultSection("LIEF logging information.", parent=request.result)
                corrupted_res = None
                for line, count in lief_logging.items():
                    if count > 1:
                        output_line = f"({count}x) {line}"
                    else:
                        output_line = line
                    res.add_line(output_line)
                    if "corrupted" in line or "Corrupted" in line:
                        if corrupted_res is None:
                            heur = Heuristic(13)
                            corrupted_res = ResultSection(heur.name, heuristic=heur, parent=res)
                        corrupted_res.add_line(output_line)
                        if line in lief_logging_stripped:
                            corrupted_res.add_line(", ".join(lief_logging_stripped[line]))

        temp_path = os.path.join(self.working_directory, "features.json")
        with open(temp_path, "w") as f:
            json.dump(self.features, f)
        request.add_supplementary(temp_path, "features.json", "Features extracted from the PE file, as a JSON file")

        # generate_ontology will modify the self.features, which is why we save it upfront
        self.generate_ontology()

    def generate_ontology(self):
        # Now that we're done processing, time to flatten the imports for storing in AL
        if "imports" in self.features:
            imports = []
            for library, functions in self.features["imports"].items():
                for func in functions:
                    func["library"] = library
                    imports.append(func)
            self.features["imports"] = imports

        # Now that we're done processing, time to flatten the resources for storing in AL
        if "resources" in self.features:
            resources = []

            def recurse_resources(node, parent_ids, parent_labels):
                if parent_ids is not None:
                    current_node_id = f"{parent_ids}.{node['resource_id']}"
                else:
                    current_node_id = str(node["resource_id"])

                node["parent_labels"] = copy.deepcopy(parent_labels)
                if "resource_type" in node and node["resource_type"] != "???":
                    parent_labels.append(node["resource_type"])
                if "name" in node:
                    parent_labels.append(node["name"])

                if node["num_childs"] > 0:
                    for child in node["childs"]:
                        recurse_resources(child, current_node_id, copy.deepcopy(parent_labels))

                if parent_ids is not None:
                    node["parent_resource_ids"] = parent_ids

                # Delete the children since they are too complicated to ingest
                if "childs" in node:
                    del node["childs"]

                # Only keep data nodes
                if node["is_data"]:
                    resources.append(node)

            recurse_resources(self.features["resources"], None, [])

            self.features["resources"] = resources

        # Now that we're done processing, time to flatten the version items for storing in AL
        if "resources_manager" in self.features:
            if "version" in self.features["resources_manager"]:
                if "string_file_info" in self.features["resources_manager"]["version"]:
                    for lancode_item in self.features["resources_manager"]["version"]["string_file_info"][
                        "langcode_items"
                    ]:
                        items = []
                        for k, v in lancode_item["items"].items():
                            items.append({"key": k, "value": v})
                        lancode_item["items"] = items
            if "html" in self.features["resources_manager"] and not self.features["resources_manager"]["html"]:
                del self.features["resources_manager"]["html"]
            if "manifest" in self.features["resources_manager"] and not self.features["resources_manager"]["manifest"]:
                del self.features["resources_manager"]["manifest"]

        # Add hr_timestamps to every timestamp found
        self.features["header"]["hr_timestamp"] = datetime.datetime.utcfromtimestamp(
            self.features["header"]["timestamp"]
        )

        if "load_configuration" in self.features:
            self.features["load_configuration"]["hr_timedatestamp"] = datetime.datetime.utcfromtimestamp(
                self.features["load_configuration"]["timedatestamp"]
            )

        if "export" in self.features:
            self.features["export"]["hr_timestamp"] = datetime.datetime.utcfromtimestamp(
                self.features["export"]["timestamp"]
            )

        if "debugs" in self.features:
            for debug in self.features["debugs"]:
                debug["hr_timestamp"] = datetime.datetime.utcfromtimestamp(debug["timestamp"])

        if "resources" in self.features:
            for resource in self.features["resources"]:
                if "time_date_stamp" in resource:
                    resource["hr_time_date_stamp"] = datetime.datetime.utcfromtimestamp(resource["time_date_stamp"])

        # And change the valid_from/valid_to of certificates
        if "signatures" in self.features:
            for signature in self.features["signatures"]:
                for signer in signature["signers"]:
                    if "cert" in signer:
                        signer["cert"]["valid_from"] = datetime.datetime(*signer["cert"]["valid_from"])
                        signer["cert"]["valid_to"] = datetime.datetime(*signer["cert"]["valid_to"])
                for certificate in signature["certificates"]:
                    certificate["valid_from"] = datetime.datetime(*certificate["valid_from"])
                    certificate["valid_to"] = datetime.datetime(*certificate["valid_to"])

        self.ontology.add_file_part(model=PE_ODM, data=self.features)
