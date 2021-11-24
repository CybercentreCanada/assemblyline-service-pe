import datetime
import hashlib
import json
import os
from io import BytesIO
from typing import Dict, List

import lief
import ordlookup
import ssdeep
from assemblyline.common.entropy import calculate_partition_entropy
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    BODY_FORMAT,
    Heuristic,
    Result,
    ResultSection,
)

import pe.al_pe

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


def from_msdos(msdos):
    """
    taken from https://0xc0decafe.com/malware-analyst-guide-to-pe-timestamps/ which was
    taken from https://github.com/digitalsleuth/time_decode
    """
    msdos = hex(msdos)[2:]
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
        (dos_year in range(1970, 2100))
        or not (dos_month in range(1, 13))
        or not (dos_day in range(1, 32))
        or not (dos_hour in range(0, 24))
        or not (dos_min in range(0, 60))
        or not (dos_sec in range(0, 60))
    ):
        return int(datetime.datetime(dos_year, dos_month, dos_day, dos_hour, dos_min, dos_sec).timestamp())
    return msdos  # Not a valid MS DOS timestamp


class PE(ServiceBase):
    def __init__(self, config=None):
        super(PE, self).__init__(config)

    def start(self):
        self.log.info("Starting PE")

    def check_timestamps(self):
        """
        Compares timestamps that could be found in the binary.
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
        if self.pe.header["timestamp"] == 708992537:  # Likely a delphi binary
            delphi = True
        elif self.pe.header["timestamp"] != 0:
            timestamps.add(self.pe.header["timestamp"])

        if hasattr(self.pe, "load_configuration") and self.pe.load_configuration["timedatestamp"] != 0:
            timestamps.add(self.pe.load_configuration["timedatestamp"])

        if hasattr(self.pe, "export") and self.pe.export["timestamp"] != 0:
            timestamps.add(self.pe.export["timestamp"])

        if hasattr(self.pe, "debug"):
            for debug in self.pe.debug:
                if debug["timestamp"] != 0:
                    timestamps.add(debug["timestamp"])
                # Will never trigger, but taken from https://0xc0decafe.com/malware-analyst-guide-to-pe-timestamps/
                if "code_view" in debug and debug["code_view"]["cv_signature"] == "01BN":
                    timestamps.add(self.pe.debug["code_view"]["signature"])

        def recurse_resources(resource):
            if "time_date_stamp" in resource and resource["time_date_stamp"] != 0:
                if delphi:
                    timestamps.add(from_msdos(resource["time_date_stamp"]))
                else:
                    timestamps.add(resource["time_date_stamp"])
            if "childs" in resource:
                for child in resource["childs"]:
                    recurse_resources(child)

        if hasattr(self.pe, "resources"):
            recurse_resources(self.pe.resources)

        if len(timestamps) > 1 and max(timestamps) - min(timestamps) > self.config.get(
            "allowed_timestamp_range", 86400
        ):
            res = ResultSection("Different timestamps", heuristic=Heuristic(11))
            for timestamp in timestamps:
                hr_timestamp = datetime.datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S +00:00 (UTC)")
                res.add_line(f"{timestamp} ({hr_timestamp})")
            self.file_res.add_section(res)

    def recurse_resources(self, resource, parent_name):
        if isinstance(resource, lief.PE.ResourceDirectory):
            if len(resource.childs) > 0:
                for child in resource.childs:
                    self.recurse_resources(child, f"{parent_name}{resource.id}_")
        elif isinstance(resource, lief.PE.ResourceData):
            if resource.content[:2] == MZ or search_list_in_list(DOS_MODE, resource.content[:200]):
                if self.temp_res is None:
                    self.temp_res = ResultSection("Executable in resources", heuristic=Heuristic(12))
                file_name = f"binary_{parent_name}{resource.id}"
                self.temp_res.add_line(f"Extracted {file_name}")
                temp_path = os.path.join(self.working_directory, file_name)
                with open(temp_path, "wb") as myfile:
                    myfile.write(bytearray(resource.content))
                self.request.add_extracted(temp_path, file_name, f"{file_name} extracted from binary's resources")

    def check_exe_resources(self):
        self.temp_res = None
        if self.lief_binary.has_resources:
            self.recurse_resources(self.lief_binary.resources, "")
        if self.temp_res is not None:
            self.file_res.add_section(self.temp_res)

    def check_dataless_resources(self):
        dataless_resources = []

        def recurse_resources(resource, parent_name):
            if resource["is_directory"]:
                if "childs" in resource:
                    for child in resource["childs"]:
                        recurse_resources(child, f"{parent_name}{resource['id']} -> ")
                else:
                    dataless_resources.append(f"{parent_name}{resource['id']}")

        if hasattr(self.pe, "resources"):
            recurse_resources(self.pe.resources, "")

        if len(dataless_resources) > 0:
            res = ResultSection("Resource directories that does not contain a leaf data node", heuristic=Heuristic(15))
            res.add_lines(dataless_resources)
            self.file_res.add_section(res)

    def calc_imphash_sha1(self):
        if not hasattr(self.pe, "imports"):
            return ""

        sorted_import_list = []
        for lib_name, entries in self.pe.imports.items():
            for entry in entries:
                if entry["name"] == "":
                    import_name = ordlookup.ordLookup(str.encode(lib_name), entry["ordinal"], make_name=False)
                    sorted_import_list.append(str(entry["ordinal"]) if import_name is None else import_name.decode())
                else:
                    sorted_import_list.append(entry["name"])

        sorted_import_list.sort()
        sorted_import_list = [str.encode(x) for x in sorted_import_list]
        return hashlib.sha1(b" ".join(sorted_import_list)).hexdigest()

    def calc_impfuzzy(self, sort=False):
        if not hasattr(self.pe, "imports"):
            return ""

        impstrs = []
        exts = ["ocx", "sys", "dll"]
        for lib_name, entries in self.pe.imports.items():
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
        return ssdeep.hash(apilist)

    def add_headers(self):
        res = ResultSection("Headers")
        res.add_line(f"Timestamp: {self.pe.header['timestamp']} ({self.pe.header['hr_timestamp']})")
        res.add_tag("file.pe.linker.timestamp", self.pe.header["timestamp"])
        res.add_tag("file.pe.linker.timestamp", self.pe.header["hr_timestamp"])
        res.add_line(f"Entrypoint: {hex(self.pe.entrypoint)}")
        res.add_line(f"Machine: {self.pe.header['machine']}")
        res.add_line(f"Magic: {self.pe.optional_header['magic']}")
        res.add_line(
            (
                f"Image version: {self.pe.optional_header['major_image_version']}."
                f"{self.pe.optional_header['minor_image_version']}"
            )
        )
        res.add_line(
            (
                f"Linker version: {self.pe.optional_header['major_linker_version']}."
                f"{self.pe.optional_header['minor_linker_version']}"
            )
        )
        res.add_line(
            (
                f"Operating System version: {self.pe.optional_header['major_operating_system_version']}."
                f"{self.pe.optional_header['minor_operating_system_version']}"
            )
        )
        res.add_line(
            (
                f"Subsystem version: {self.pe.optional_header['major_subsystem_version']}."
                f"{self.pe.optional_header['minor_subsystem_version']}"
            )
        )
        res.add_line(f"Subsystem: {self.pe.optional_header['subsystem']}")
        res.add_line(f"NX: {self.pe.nx}")
        if hasattr(self.pe, "rich_header"):
            sub_res = ResultSection(f"Rich Headers - Key: {self.pe.rich_header['key']}")
            for entry in self.pe.rich_header["entries"]:
                sub_res.add_line(f"build_id: {entry['build_id']}, count: {entry['count']}, id: {entry['id']}")
            res.add_subsection(sub_res)
        sub_res = ResultSection("Authentihash")
        for h, v in self.pe.authentihash.items():
            sub_res.add_line(f"{h}: {v}")
        res.add_subsection(sub_res)
        res.add_line(f"Position Independent: {self.pe.position_independent}")

        overlay = bytes.fromhex(self.pe.overlay)
        res.add_line(f"Overlay size: {len(overlay)}")
        if len(overlay) > 0:
            file_name = "overlay"
            temp_path = os.path.join(self.working_directory, file_name)
            with open(temp_path, "wb") as myfile:
                myfile.write(overlay)
            self.request.add_extracted(temp_path, file_name, f"{file_name} extracted from binary's resources")

        self.file_res.add_section(res)

    def add_sections(self):
        res = ResultSection("Sections")
        for section in self.pe.sections:
            sub_res = ResultSection(f"Section - {section['name']}")
            sub_res.add_tag("file.pe.sections.name", section["name"])
            sub_res.add_line(f"Entropy: {section['entropy']}")
            if section["entropy"] > 7.5:
                sub_res.set_heuristic(4)
            sub_res.add_line(f"Entropy without padding: {section['entropy_without_padding']}")
            sub_res.add_line(f"Offset: {section['offset']}")
            sub_res.add_line(f"Size: {section['size']}")
            sub_res.add_line(f"Virtual Size: {section['virtual_size']}")
            sub_res.add_line(f"Characteristics: {', '.join(section['characteristics_list'])}")
            sub_res.add_line(f"MD5: {section['md5']}")
            sub_res.add_tag("file.pe.sections.hash", section["md5"])

            try:
                lief_section = self.lief_binary.get_section(section["name"])
                if lief_section.size > len(lief_section.content):
                    full_section_data = bytearray(lief_section.content) + lief_section.padding
                else:
                    full_section_data = bytearray(lief_section.content)

                entropy_graph_data = {
                    "type": "colormap",
                    "data": {"domain": [0, 8], "values": calculate_partition_entropy(BytesIO(full_section_data))[1]},
                }
                sub_sub_res = ResultSection(
                    "Entropy graph", body_format=BODY_FORMAT.GRAPH_DATA, body=json.dumps(entropy_graph_data)
                )
                sub_res.add_subsection(sub_sub_res)
            except lief.not_found:
                sub_sub_res = ResultSection(
                    "Section could not be retrieved using the section's name.", heuristic=Heuristic(14)
                )
                sub_res.add_subsection(sub_sub_res)

            res.add_subsection(sub_res)
        self.file_res.add_section(res)

    def add_debug(self):
        if not hasattr(self.pe, "debug"):
            return
        res = ResultSection("Debug")
        for debug in self.pe.debug:
            sub_res = ResultSection(f"{debug['type']}")
            hr_timestamp = datetime.datetime.utcfromtimestamp(debug["timestamp"]).strftime(
                "%Y-%m-%d %H:%M:%S +00:00 (UTC)"
            )
            sub_res.add_line(f"Timestamp: {debug['timestamp']} ({hr_timestamp})")
            sub_res.add_line(f"Version: {debug['major_version']}.{debug['minor_version']}")
            if "code_view" in debug:
                sub_res.add_line(f"CV_Signature: {debug['code_view']['cv_signature']}")
                if "filename" in debug["code_view"]:
                    sub_res.add_line(f"Filename: {debug['code_view']['filename']}")
                    sub_res.add_tag("file.pe.pdb_filename", debug["code_view"]["filename"])
                else:
                    # No filename specified, test the binary to make sure it's corrupted.
                    try:
                        for binary_debug in self.lief_binary.debug:
                            if binary_debug.has_code_view:
                                binary_debug.code_view.filename
                    except UnicodeDecodeError:
                        sub_res.set_heuristic(16)
            if "pogo" in debug:
                sub_sub_res = ResultSection(f"POGO - {debug['pogo']['signature']}")
                for entry in debug["pogo"]["entries"]:
                    sub_sub_res.add_line(f"Name: {entry['name']}, Size: {entry['size']}")
                sub_res.add_subsection(sub_sub_res)
            res.add_subsection(sub_res)
        self.file_res.add_section(res)

    def add_exports(self):
        if not hasattr(self.pe, "export"):
            return
        res = ResultSection("Exports")
        res.add_line(f"Name: {self.pe.export['name']}")
        res.add_tag("file.pe.exports.module_name", self.pe.export["name"])
        res.add_line(f"Version: {self.pe.export['major_version']}.{self.pe.export['minor_version']}")
        hr_timestamp = datetime.datetime.utcfromtimestamp(self.pe.export["timestamp"]).strftime(
            "%Y-%m-%d %H:%M:%S +00:00 (UTC)"
        )
        res.add_line(f"Timestamp: {self.pe.export['timestamp']} ({hr_timestamp})")
        sub_res = ResultSection("Entries")
        for entry in self.pe.export["entries"]:
            sub_res.add_line(f"Name: {entry['name']}, ordinal: {entry['ordinal']}")
            sub_res.add_tag("file.pe.exports.function_name", entry["name"])
        res.add_subsection(sub_res)
        self.file_res.add_section(res)

    def add_imports(self):
        if not hasattr(self.pe, "imports"):
            return
        res = ResultSection("Imports")
        for lib_name, entries in self.pe.imports.items():
            sub_res = ResultSection(f"{lib_name}")
            sub_res.add_line(
                ", ".join([str(entry["ordinal"]) if entry["is_ordinal"] else str(entry["name"]) for entry in entries])
            )
            res.add_subsection(sub_res)
        res.add_tag("file.pe.imports.sorted_sha1", self.calc_imphash_sha1())
        res.add_tag("file.pe.imports.md5", self.pe.imphash)
        res.add_tag("file.pe.imports.fuzzy", self.calc_impfuzzy(sort=False))
        res.add_tag("file.pe.imports.sorted_fuzzy", self.calc_impfuzzy(sort=True))
        self.file_res.add_section(res)

    def add_resources(self):
        if not hasattr(self.pe, "resources"):
            return
        res = ResultSection("Resources")
        res.add_line(f"Languages available: {', '.join(self.pe.resources_manager['langs_available'])}")
        for lang in self.pe.resources_manager["langs_available"]:
            res.add_tag("file.pe.resources.language", lang)
        res.add_line(f"Sublanguages available: {', '.join(self.pe.resources_manager['sublangs_available'])}")
        if "icons" in self.pe.resources_manager:
            sub_res = ResultSection("Icons")
            for icon in self.pe.resources_manager["icons"]:
                sub_res.add_line(f"ID: {icon['id']}, Lang: {icon['lang']}")
            res.add_subsection(sub_res)
        if "manifest" in self.pe.resources_manager:
            res.add_line(f"Manifest: {self.pe.resources_manager['manifest']}")

        # Not going to put all strings, but will do dialogs titles.
        if "dialogs" in self.pe.resources_manager:
            for dialog in self.pe.resources_manager["dialogs"]:
                if dialog["title"] != "":
                    res.add_tag("file.string.extracted", dialog["title"])
                for item in dialog["items"]:
                    if item["title"] != "":
                        res.add_tag("file.string.extracted", item["title"])

        def generate_subsections(data, title):
            gen_res = ResultSection(title)
            for k, v in data.items():
                if isinstance(v, Dict):
                    gen_res.add_subsection(generate_subsections(v, k))
                elif isinstance(v, List):
                    for item_index, item in enumerate(v):
                        if isinstance(item, Dict):
                            gen_res.add_subsection(generate_subsections(item, f"{k} {item_index + 1}"))
                        else:
                            gen_res.add_line(f"{k}: {item}")
                else:
                    gen_res.add_line(f"{k}: {v}")
            return gen_res

        if "version" in self.pe.resources_manager:
            sub_res = ResultSection("Version")
            sub_res.add_line(f"Type: {self.pe.resources_manager['version']['type']}")
            if "fixed_file_info" in self.pe.resources_manager["version"]:
                sub_res.add_subsection(
                    generate_subsections(self.pe.resources_manager["version"]["fixed_file_info"], "fixed_file_info")
                )
            if "string_file_info" in self.pe.resources_manager["version"]:
                string_file_sub_res = generate_subsections(
                    self.pe.resources_manager["version"]["string_file_info"], "string_file_info"
                )
                for langcode_items in self.pe.resources_manager["version"]["string_file_info"]["langcode_items"]:
                    if "OriginalFilename" in langcode_items["items"]:
                        string_file_sub_res.add_tag(
                            "file.pe.versions.filename", langcode_items["items"]["OriginalFilename"]
                        )
                    if "FileDescription" in langcode_items["items"]:
                        string_file_sub_res.add_tag(
                            "file.pe.versions.description", langcode_items["items"]["FileDescription"]
                        )
                sub_res.add_subsection(string_file_sub_res)
            if "var_file_info" in self.pe.resources_manager["version"]:
                sub_res.add_subsection(
                    generate_subsections(self.pe.resources_manager["version"]["var_file_info"], "var_file_info")
                )
            res.add_subsection(sub_res)

        def recurse_resources(resource):
            if "name" in resource:
                res.add_tag("file.pe.resources.name", resource["name"])
            if "childs" in resource:
                for child in resource["childs"]:
                    recurse_resources(child)

        recurse_resources(self.pe.resources)

        self.file_res.add_section(res)

    def add_signatures(self):
        if not hasattr(self.pe, "signatures"):
            return

        res = ResultSection("Signatures")

        if "INVALID_SIGNER" in self.pe.verify_signature:
            res.add_subsection(ResultSection("Invalid PE Signature detected", heuristic=Heuristic(10)))

        if self.pe.verify_signature == "OK":
            res.add_subsection(ResultSection("This file is signed", heuristic=Heuristic(2)))

        for signature_index, signature in enumerate(self.pe.signatures):
            sub_res = ResultSection(f"Signature - {signature_index + 1}")
            sub_res.add_line(f"Version: {signature['version']}")
            sub_res.add_line(f"Algorithm: {signature['algorithm']}")
            sub_res.add_line(f"Content Info Algorithm: {signature['content_info']['algorithm']}")
            sub_res.add_line(f"Content Info Digest: {signature['content_info']['digest']}")
            sub_res.add_line(f"Content Info Content Type: {signature['content_info']['content_type']}")
            for signer_index, signer in enumerate(signature["signers"]):
                sub_sub_res = ResultSection(f"Signer - {signer_index + 1}")
                sub_sub_res.add_line(f"Version: {signer['version']}")
                sub_sub_sub_res = ResultSection("Signer Certificate")
                sub_sub_sub_res.add_line(f"Version: {signer['cert']['version']}")
                sub_sub_sub_res.add_line(f"Subject: {signer['cert']['subject']}")
                sub_sub_sub_res.add_tag("cert.subject", signer["cert"]["subject"])
                sub_sub_sub_res.add_line(f"Issuer: {signer['cert']['issuer']}")
                sub_sub_sub_res.add_tag("cert.issuer", signer["cert"]["issuer"])
                sub_sub_sub_res.add_line(f"Serial Number: {signer['cert']['serial_number']}")
                sub_sub_sub_res.add_tag("cert.serial_no", signer["cert"]["serial_number"])
                sub_sub_sub_res.add_line(f"Valid From: {datetime.datetime(*signer['cert']['valid_from']).isoformat()}")
                sub_sub_sub_res.add_tag(
                    "cert.valid.start", datetime.datetime(*signer["cert"]["valid_from"]).isoformat()
                )
                sub_sub_sub_res.add_line(f"Valid To: {datetime.datetime(*signer['cert']['valid_to']).isoformat()}")
                sub_sub_sub_res.add_tag("cert.valid.end", datetime.datetime(*signer["cert"]["valid_to"]).isoformat())
                # The sha1 thumbprint generated this way match what VirusTotal reports for 'certificate thumbprints'
                sub_sub_sub_res.add_tag(
                    "cert.thumbprint", hashlib.sha1(bytes.fromhex(signer["cert"]["raw_hex"])).hexdigest()
                )
                sub_sub_sub_res.add_tag(
                    "cert.thumbprint", hashlib.sha256(bytes.fromhex(signer["cert"]["raw_hex"])).hexdigest()
                )
                sub_sub_sub_res.add_tag(
                    "cert.thumbprint", hashlib.md5(bytes.fromhex(signer["cert"]["raw_hex"])).hexdigest()
                )
                sub_sub_res.add_subsection(sub_sub_sub_res)
                sub_sub_res.add_line(f"Digest Algorithm: {signer['digest_algorithm']}")
                sub_sub_res.add_line(f"Authenticated Attributes: {', '.join(signer['authenticated_attributes'])}")
                sub_sub_res.add_line(f"Unauthenticated Attributes: {', '.join(signer['unauthenticated_attributes'])}")
                sub_res.add_subsection(sub_sub_res)
            for certificate_index, certificate in enumerate(signature["certificates"]):
                sub_sub_res = ResultSection(f"Certificate - {certificate_index + 1}")
                sub_sub_res.add_line(f"Version: {certificate['version']}")
                sub_sub_res.add_line(f"Subject: {certificate['subject']}")
                sub_sub_res.add_line(f"Issuer: {certificate['issuer']}")
                raw_cert = bytes.fromhex(certificate["raw_hex"])
                file_name = f"certificate.{signature_index + 1}.{certificate_index + 1}"
                temp_path = os.path.join(self.working_directory, file_name)
                with open(temp_path, "wb") as myfile:
                    myfile.write(raw_cert)
                self.request.add_extracted(temp_path, file_name, f"{file_name} extracted from binary's resources")
                sub_sub_res.add_line(f"SHA-1: {hashlib.sha1(raw_cert).hexdigest()}")
                sub_sub_res.add_line(f"SHA-256: {hashlib.sha256(raw_cert).hexdigest()}")
                sub_sub_res.add_line(f"MD5: {hashlib.md5(raw_cert).hexdigest()}")
                sub_sub_res.add_line(f"Serial Number: {certificate['serial_number']}")
                sub_sub_res.add_line(f"Valid From: {datetime.datetime(*certificate['valid_from']).isoformat()}")
                sub_sub_res.add_line(f"Valid To: {datetime.datetime(*certificate['valid_to']).isoformat()}")
                sub_res.add_subsection(sub_sub_res)

            if signature["content_info"]["algorithm"] not in self.pe.authentihash:
                sub_res.add_subsection(
                    ResultSection("The signature does not match the program data", heuristic=Heuristic(1))
                )
            elif signature["content_info"]["digest"] != self.pe.authentihash[signature["content_info"]["algorithm"]]:
                sub_res.add_subsection(
                    ResultSection("The signature does not match the program data", heuristic=Heuristic(1))
                )

            if len(signature["certificates"]) < 2:
                sub_res.add_subsection(
                    ResultSection(
                        "This is probably an error. Less than 2 certificates were found", heuristic=Heuristic(8)
                    )
                )
                res.add_subsection(sub_res)
                continue

            self_signed_signer = False
            denied_algorithm = False
            for signer in signature["signers"]:
                if signer["encryption_algorithm"] not in ACCEPTED_ALGORITHMS:
                    denied_algorithm = True
                if signer["cert"]["issuer"] == signer["cert"]["subject"] and signer["cert"]["is_trusted"] != "OK":
                    self_signed_signer = True
                    break

            if denied_algorithm:
                exploit_res = ResultSection("Invalid Encryption Algorithm used for signature", heuristic=Heuristic(9))
                exploit_res.add_tag("attribution.exploit", "CVE_2020_0601")
                sub_res.add_subsection(exploit_res)
                res.add_subsection(sub_res)
                continue

            if self_signed_signer:
                sub_res.add_subsection(
                    ResultSection("File is self-signed (signing cert signed by itself)", heuristic=Heuristic(6))
                )
                res.add_subsection(sub_res)
                continue

            first_issuer = signature["certificates"][0]["issuer"]
            all_same_issuer = True
            for cert in signature["certificates"]:
                if cert["issuer"] != first_issuer:
                    all_same_issuer = False
                    break
            if all_same_issuer:
                sub_res.add_subsection(
                    ResultSection("File is self-signed, all certificate issuers match", heuristic=Heuristic(3))
                )
                res.add_subsection(sub_res)
                continue

            if signature["check"] != "OK":
                sub_res.add_subsection(
                    ResultSection(
                        "Possibly self signed. "
                        "Could not identify a chain of trust back to a known root CA, but certificates "
                        "presented were issued by different issuers",
                        heuristic=Heuristic(5),
                    )
                )
            res.add_subsection(sub_res)
        self.file_res.add_section(res)

    def execute(self, request: ServiceRequest):
        request.result = Result()
        self.file_res = request.result
        self.request = request

        self.lief_binary = lief.parse(request.file_path)
        if self.lief_binary is None:
            res = ResultSection("This file looks like a PE but failed loading.", heuristic=Heuristic(7))
            self.file_res.add_section(res)
            return

        self.pe = pe.al_pe.AL_PE(
            binary=self.lief_binary,
            trusted_certs_paths=self.config.get("trusted_certs", []),
            extract_relocations=request.deep_scan,
        )

        self.check_timestamps()
        self.check_exe_resources()
        self.check_dataless_resources()

        self.add_headers()
        self.add_sections()
        self.add_debug()
        self.add_exports()
        self.add_imports()
        self.add_resources()
        self.add_signatures()

        if self.lief_binary.has_resources and self.lief_binary.resources_manager.has_icons:
            try:
                for idx, icon in enumerate(self.lief_binary.resources_manager.icons):
                    temp_path = os.path.join(self.working_directory, f"icon_{idx}.ico")
                    icon.save(temp_path)
                    request.add_supplementary(temp_path, f"icon_{idx}.ico", f"Icon {idx} extracted from the PE file")
            except lief.corrupted:
                res = ResultSection("This file contains heavily corrupted resources.", heuristic=Heuristic(13))
                self.file_res.add_section(res)

        temp_path = os.path.join(self.working_directory, "al_pe.json")
        with open(temp_path, "w") as myfile:
            myfile.write(json.dumps(self.pe.__dict__))
        request.add_supplementary(temp_path, "al_pe.json", "Features extracted from the PE file, as a JSON file")
