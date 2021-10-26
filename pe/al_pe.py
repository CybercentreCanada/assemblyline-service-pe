import datetime
import os
from collections import defaultdict

import lief

cert_verification_entries = {
    entry.__int__(): entry for entry, txt in lief.PE.x509.VERIFICATION_FLAGS.__entries.values()
}


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


def extract_cert_info(cert, trusted_certs):
    cert_struct = {
        "version": cert.version,
        "subject": cert.subject,
        "issuer": cert.issuer,
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
            "D": cert.rsa_info.D.hex(),
            "E": cert.rsa_info.E.hex(),
            "N": cert.rsa_info.N.hex(),
            "P": cert.rsa_info.P.hex(),
            "Q": cert.rsa_info.Q.hex(),
        }
        cert_struct["key_size"] = cert.rsa_info.key_size
    return cert_struct


class AL_PE:
    def __init__(
        self,
        data=None,
        trusted_certs_paths=["/usr/share/ca-certificates/mozilla/"],
        binary=None,
        extract_relocations=False,
    ):
        if data is not None:
            self.__dict__.update(data)
            return

        self.name = binary.name
        self.format = binary.format.name
        self.imphash = lief.PE.get_imphash(binary, mode=lief.PE.IMPHASH_MODE.PEFILE)
        self.entrypoint = (
            binary.optional_header.addressof_entrypoint
        )  # Somehow, that is different from binary.entrypoint
        self.header = {
            "characteristics_hash": binary.header.characteristics.__int__(),
            "characteristics_list": [char.name for char in binary.header.characteristics_list],
            "machine": binary.header.machine.name,
            "numberof_sections": binary.header.numberof_sections,
            "numberof_symbols": binary.header.numberof_symbols,
            "signature": binary.header.signature,
            "timestamp": binary.header.time_date_stamps,
            "hr_timestamp": datetime.datetime.utcfromtimestamp(binary.header.time_date_stamps).strftime(
                "%Y-%m-%d %H:%M:%S +00:00 (UTC)"
            ),
        }
        self.optional_header = {
            "addressof_entrypoint": binary.optional_header.addressof_entrypoint,
            "baseof_code": binary.optional_header.baseof_code,
            "checksum": binary.optional_header.checksum,
            "dll_characteristics": binary.optional_header.dll_characteristics,
            "dll_characteristics_lists": [char.name for char in binary.optional_header.dll_characteristics_lists],
            "file_alignment": binary.optional_header.file_alignment,
            "imagebase": binary.optional_header.imagebase,
            "loader_flags": binary.optional_header.loader_flags,
            "magic": binary.optional_header.magic.name,
            "major_image_version": binary.optional_header.major_image_version,
            "major_linker_version": binary.optional_header.major_linker_version,
            "major_operating_system_version": binary.optional_header.major_operating_system_version,
            "major_subsystem_version": binary.optional_header.major_subsystem_version,
            "minor_image_version": binary.optional_header.minor_image_version,
            "minor_linker_version": binary.optional_header.minor_linker_version,
            "minor_operating_system_version": binary.optional_header.minor_operating_system_version,
            "minor_subsystem_version": binary.optional_header.minor_subsystem_version,
            "numberof_rva_and_size": binary.optional_header.numberof_rva_and_size,
            "section_alignment": binary.optional_header.section_alignment,
            "sizeof_code": binary.optional_header.sizeof_code,
            "sizeof_headers": binary.optional_header.sizeof_headers,
            "sizeof_heap_commit": binary.optional_header.sizeof_heap_commit,
            "sizeof_heap_reserve": binary.optional_header.sizeof_heap_reserve,
            "sizeof_image": binary.optional_header.sizeof_image,
            "sizeof_initialized_data": binary.optional_header.sizeof_initialized_data,
            "sizeof_stack_commit": binary.optional_header.sizeof_stack_commit,
            "sizeof_stack_reserve": binary.optional_header.sizeof_stack_reserve,
            "sizeof_uninitialized_data": binary.optional_header.sizeof_uninitialized_data,
            "subsystem": binary.optional_header.subsystem.name,
            "win32_version_value": binary.optional_header.win32_version_value,
        }
        if binary.optional_header.magic != lief.PE.PE_TYPE.PE32_PLUS:
            self.optional_header["baseof_data"] = binary.optional_header.baseof_data

        self.nx = binary.has_nx
        self.sections = []
        for section in binary.sections:
            section_dict = {
                "name": section.name,
                "characteristics_hash": section.characteristics,
                "characteristics_list": [char.name for char in section.characteristics_lists],
                "entropy": section.entropy,
                "offset": section.offset,
                "size": section.size,
                "sizeof_raw_data": section.sizeof_raw_data,
                "virtual_address": section.virtual_address,
                "virtual_size": section.virtual_size,
            }
            if hasattr(section, "fullname"):
                section_dict["fullname"] = section.fullname

            self.sections.append(section_dict)

        self.authentihash = {
            lief.PE.ALGORITHMS(i).name: binary.authentihash(lief.PE.ALGORITHMS(i)).hex() for i in range(1, 6)
        }

        if binary.has_debug:
            self.debug = []
            for debug in binary.debug:
                debug_dict = {
                    "addressof_rawdata": debug.addressof_rawdata,
                    "characteristics": debug.characteristics,
                    "major_version": debug.major_version,
                    "minor_version": debug.minor_version,
                    "pointerto_rawdata": debug.pointerto_rawdata,
                    "sizeof_data": debug.sizeof_data,
                    "timestamp": debug.timestamp,
                    "type": debug.type.name,
                }
                if debug.has_code_view:
                    debug_dict["code_view"] = {
                        "age": debug.code_view.age,
                        "cv_signature": debug.code_view.cv_signature.name,
                        "filename": debug.code_view.filename,
                        "signature": debug.code_view.signature,
                    }
                if debug.has_pogo:
                    debug_dict["pogo"] = {
                        "entries": [
                            {
                                "name": pogo.name,
                                "size": pogo.size,
                                "start_rva": pogo.start_rva,
                            }
                            for pogo in debug.pogo.entries
                        ],
                        "signature": debug.pogo.signature.name,
                    }
                self.debug.append(debug_dict)

        self.dos_header = {
            "addressof_new_exeheader": binary.dos_header.addressof_new_exeheader,
            "addressof_relocation_table": binary.dos_header.addressof_relocation_table,
            "checksum": binary.dos_header.checksum,
            "file_size_in_pages": binary.dos_header.file_size_in_pages,
            "header_size_in_paragraphs": binary.dos_header.header_size_in_paragraphs,
            "initial_ip": binary.dos_header.initial_ip,
            "initial_relative_cs": binary.dos_header.initial_relative_cs,
            "initial_relative_ss": binary.dos_header.initial_relative_ss,
            "initial_sp": binary.dos_header.initial_sp,
            "magic": binary.dos_header.magic,
            "maximum_extra_paragraphs": binary.dos_header.maximum_extra_paragraphs,
            "minimum_extra_paragraphs": binary.dos_header.minimum_extra_paragraphs,
            "numberof_relocation": binary.dos_header.numberof_relocation,
            "oem_id": binary.dos_header.oem_id,
            "oem_info": binary.dos_header.oem_info,
            "overlay_number": binary.dos_header.overlay_number,
            "used_bytes_in_the_last_page": binary.dos_header.used_bytes_in_the_last_page,
        }

        if binary.has_exceptions:
            # TODO: What is this has_exceptions supposed to be linked to?
            # A lot of executables seems to have this flag set to True
            pass

        # TODO: Do we want to show them all?
        # print(binary.exception_functions)
        # print(binary.functions)
        # print(binary.imported_functions)
        # print(binary.exported_functions)

        if binary.has_exports:
            self.export = {
                "entries": [
                    {
                        "address": entry.address,
                        "forward_information": {
                            "function": entry.forward_information.function,
                            "library": entry.forward_information.library,
                        },
                        "function_rva": entry.function_rva,
                        "is_extern": entry.is_extern,
                        "name": entry.name,
                        "ordinal": entry.ordinal,
                        # "size": entry.size, #In the docs, but not in the dir()
                        # "value": entry.value, #In the docs, but not in the dir()
                    }
                    for entry in binary.get_export().entries
                ],
                "export_flags": binary.get_export().export_flags,
                "major_version": binary.get_export().major_version,
                "minor_version": binary.get_export().minor_version,
                "name": binary.get_export().name,
                "ordinal_base": binary.get_export().ordinal_base,
                "timestamp": binary.get_export().timestamp,
            }

        if binary.has_configuration:
            self.load_configuration = {
                "characteristics": binary.load_configuration.characteristics,
                "critical_section_default_timeout": binary.load_configuration.critical_section_default_timeout,
                "csd_version": binary.load_configuration.csd_version,
                "decommit_free_block_threshold": binary.load_configuration.decommit_free_block_threshold,
                "decommit_total_free_threshold": binary.load_configuration.decommit_total_free_threshold,
                "editlist": binary.load_configuration.editlist,
                "global_flags_clear": binary.load_configuration.global_flags_clear,
                "global_flags_set": binary.load_configuration.global_flags_set,
                "lock_prefix_table": binary.load_configuration.lock_prefix_table,
                "major_version": binary.load_configuration.major_version,
                "maximum_allocation_size": binary.load_configuration.maximum_allocation_size,
                "minor_version": binary.load_configuration.minor_version,
                "process_affinity_mask": binary.load_configuration.process_affinity_mask,
                "process_heap_flags": binary.load_configuration.process_heap_flags,
                "reserved1": binary.load_configuration.reserved1,
                "security_cookie": binary.load_configuration.security_cookie,
                "timedatestamp": binary.load_configuration.timedatestamp,
                "version": binary.load_configuration.version.name,
                "virtual_memory_threshold": binary.load_configuration.virtual_memory_threshold,
            }

            def set_config_v0():
                self.load_configuration["se_handler_count"] = binary.load_configuration.se_handler_count
                self.load_configuration["se_handler_table"] = binary.load_configuration.se_handler_table

            def set_config_v1():
                set_config_v0()

                self.load_configuration[
                    "guard_cf_check_function_pointer"
                ] = binary.load_configuration.guard_cf_check_function_pointer
                self.load_configuration[
                    "guard_cf_dispatch_function_pointer"
                ] = binary.load_configuration.guard_cf_dispatch_function_pointer
                self.load_configuration["guard_cf_flags_list"] = [
                    guard_flag.name for guard_flag in binary.load_configuration.guard_cf_flags_list
                ]
                self.load_configuration["guard_cf_function_count"] = binary.load_configuration.guard_cf_function_count
                self.load_configuration["guard_cf_function_table"] = binary.load_configuration.guard_cf_function_table
                self.load_configuration["guard_flags"] = binary.load_configuration.guard_flags.name

            def set_config_v2():
                set_config_v1()
                self.load_configuration["code_integrity"] = {
                    "catalog": binary.load_configuration.code_integrity.catalog,
                    "catalog_offset": binary.load_configuration.code_integrity.catalog_offset,
                    "flags": binary.load_configuration.code_integrity.flags,
                    "reserved": binary.load_configuration.code_integrity.reserved,
                }

            def set_config_v3():
                set_config_v2()
                self.load_configuration[
                    "guard_address_taken_iat_entry_count"
                ] = binary.load_configuration.guard_address_taken_iat_entry_count
                self.load_configuration[
                    "guard_address_taken_iat_entry_table"
                ] = binary.load_configuration.guard_address_taken_iat_entry_table
                self.load_configuration[
                    "guard_long_jump_target_count"
                ] = binary.load_configuration.guard_long_jump_target_count
                self.load_configuration[
                    "guard_long_jump_target_table"
                ] = binary.load_configuration.guard_long_jump_target_table

            def set_config_v4():
                set_config_v3()
                self.load_configuration[
                    "dynamic_value_reloc_table"
                ] = binary.load_configuration.dynamic_value_reloc_table
                self.load_configuration["hybrid_metadata_pointer"] = binary.load_configuration.hybrid_metadata_pointer

            def set_config_v5():
                set_config_v4()
                self.load_configuration[
                    "dynamic_value_reloctable_offset"
                ] = binary.load_configuration.dynamic_value_reloctable_offset
                self.load_configuration[
                    "dynamic_value_reloctable_section"
                ] = binary.load_configuration.dynamic_value_reloctable_section
                self.load_configuration["guard_rf_failure_routine"] = binary.load_configuration.guard_rf_failure_routine
                self.load_configuration[
                    "guard_rf_failure_routine_function_pointer"
                ] = binary.load_configuration.guard_rf_failure_routine_function_pointer
                self.load_configuration["reserved2"] = binary.load_configuration.reserved2

            def set_config_v6():
                set_config_v5()
                self.load_configuration[
                    "guard_rf_verify_stackpointer_function_pointer"
                ] = binary.load_configuration.guard_rf_verify_stackpointer_function_pointer
                self.load_configuration["hotpatch_table_offset"] = binary.load_configuration.hotpatch_table_offset

            def set_config_v7():
                set_config_v6()
                self.load_configuration["addressof_unicode_string"] = binary.load_configuration.addressof_unicode_string
                self.load_configuration["reserved3"] = binary.load_configuration.reserved3

            if isinstance(binary.load_configuration, lief.PE.LoadConfigurationV7):
                set_config_v7()
            elif isinstance(binary.load_configuration, lief.PE.LoadConfigurationV6):
                set_config_v6()
            elif isinstance(binary.load_configuration, lief.PE.LoadConfigurationV5):
                set_config_v5()
            elif isinstance(binary.load_configuration, lief.PE.LoadConfigurationV4):
                set_config_v4()
            elif isinstance(binary.load_configuration, lief.PE.LoadConfigurationV3):
                set_config_v3()
            elif isinstance(binary.load_configuration, lief.PE.LoadConfigurationV2):
                set_config_v2()
            elif isinstance(binary.load_configuration, lief.PE.LoadConfigurationV1):
                set_config_v1()
            elif isinstance(binary.load_configuration, lief.PE.LoadConfigurationV0):
                set_config_v0()

        if binary.has_imports:
            self.imports = defaultdict(list)
            for lib in binary.imports:
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
                    self.imports[lib.name].append(entry_dict)

        if extract_relocations and binary.has_relocations:
            self.relocations = [
                {
                    "virtual_address": relocation.virtual_address,
                    "entries": [
                        {
                            "address": entrie.address,
                            "data": entrie.data,
                            "position": entrie.position,
                            "size": entrie.size,
                            "type": entrie.type.name,
                        }
                        for entrie in relocation.entries
                    ],
                }
                for relocation in binary.relocations
            ]

        if binary.has_resources:
            self.resources_manager = {
                "langs_available": [lang.name for lang in binary.resources_manager.langs_available],
                "sublangs_available": [lang.name for lang in binary.resources_manager.sublangs_available],
            }
            if binary.resources_manager.has_accelerator:
                # TODO: Find a binary with accelerator, There is no doc for it?
                print(binary.resources_manager.accelerator)
                raise Exception("Found a binary with accelerator", self.name)
            if binary.resources_manager.has_dialogs:
                self.resources_manager["dialogs"] = [
                    {
                        "charset": dialog.charset,
                        "cx": dialog.cx,
                        "cy": dialog.cy,
                        "dialogbox_style_list": [
                            dialogbox_style.name for dialogbox_style in dialog.dialogbox_style_list
                        ],
                        "extended_style": str(dialog.extended_style),  # .name
                        "extended_style_list": [extended_style.name for extended_style in dialog.extended_style_list],
                        "help_id": dialog.help_id,
                        "items": [
                            {
                                "cx": item.cx,
                                "cy": item.cy,
                                "extended_style": item.extended_style,
                                "help_id": item.help_id,
                                "id": item.id,
                                "is_extended": item.is_extended,
                                "style": str(item.style),  # .name
                                "title": item.title,
                                "x": item.x,
                                "y": item.y,
                            }
                            for item in dialog.items
                        ],
                        "lang": dialog.lang.name,
                        "point_size": dialog.point_size,
                        "signature": dialog.signature,
                        "style": str(dialog.style),  # .name
                        "style_list": [style.name for style in dialog.style_list],
                        "sub_lang": dialog.sub_lang.name,
                        "title": dialog.title,
                        "typeface": dialog.typeface,
                        "version": dialog.version,
                        "weight": dialog.weight,
                        "x": dialog.x,
                        "y": dialog.y,
                    }
                    for dialog in binary.resources_manager.dialogs
                ]
            if binary.resources_manager.has_html:
                self.resources_manager["html"] = binary.resources_manager.html
            if binary.resources_manager.has_icons:
                self.resources_manager["icons"] = [
                    {
                        "id": icon.id,
                        # "pixels": icon.pixels,
                        "planes": icon.planes,
                        "height": icon.height,
                        "width": icon.width,
                        "lang": icon.lang.name,
                        "sublang": icon.sublang.name,
                    }
                    for icon in binary.resources_manager.icons
                ]
            if binary.resources_manager.has_manifest:
                self.resources_manager["manifest"] = binary.resources_manager.manifest
            if binary.resources_manager.has_string_table:
                self.resources_manager["string_table"] = []
                for string_table in binary.resources_manager.string_table:
                    try:
                        self.resources_manager["string_table"].append(string_table.name)
                    except UnicodeDecodeError:
                        self.resources_manager["string_table"].append("AL_PE: UnicodeDecodeError")
                        pass
            if binary.resources_manager.has_version:
                version = binary.resources_manager.version
                self.resources_manager["version"] = {"type": version.type}
                if version.has_fixed_file_info:
                    self.resources_manager["version"]["fixed_file_info"] = {
                        "file_date_LS": version.fixed_file_info.file_date_LS,
                        "file_date_MS": version.fixed_file_info.file_date_MS,
                        "file_flags": version.fixed_file_info.file_flags,
                        "file_flags_mask": version.fixed_file_info.file_flags_mask,
                        "file_os": version.fixed_file_info.file_os.name,
                        "file_subtype": version.fixed_file_info.file_subtype.name,
                        "file_type": version.fixed_file_info.file_type.name,
                        "file_version_LS": version.fixed_file_info.file_version_LS,
                        "file_version_MS": version.fixed_file_info.file_version_MS,
                        "product_version_LS": version.fixed_file_info.product_version_LS,
                        "product_version_MS": version.fixed_file_info.product_version_MS,
                        "signature": version.fixed_file_info.signature,
                        "struct_version": version.fixed_file_info.struct_version,
                    }
                if version.has_string_file_info:
                    self.resources_manager["version"]["string_file_info"] = {
                        "key": version.string_file_info.key,
                        "type": version.string_file_info.type,
                        "langcode_items": [
                            {
                                "key": langcodeitem.key,
                                "type": langcodeitem.type,
                                "lang": langcodeitem.lang.name,
                                "sublang": langcodeitem.sublang.name,
                                "code_page": langcodeitem.code_page.name,
                                "items": {k: v.decode() for k, v in langcodeitem.items.items()},
                            }
                            for langcodeitem in version.string_file_info.langcode_items
                        ],
                    }
                if version.has_var_file_info:
                    self.resources_manager["version"]["var_file_info"] = {
                        "key": version.var_file_info.key,
                        "type": version.var_file_info.type,
                        "translations": version.var_file_info.translations,
                    }

            self.resources = self.get_node_data(binary.resources)

        if binary.has_rich_header:
            self.rich_header = {
                "entries": [
                    {
                        "build_id": entry.build_id,
                        "count": entry.count,
                        "id": entry.id,
                    }
                    for entry in binary.rich_header.entries
                ],
                "key": binary.rich_header.key,
            }

        self.verify_signature = binary.verify_signature().name()

        if binary.has_signatures:
            all_certs = [
                lief.PE.x509.parse(f"{trusted_certs_path}{x}")
                for trusted_certs_path in trusted_certs_paths
                for x in os.listdir(trusted_certs_path)
            ]
            trusted_certs = [item for sublist in all_certs for item in sublist]
            if len(binary.signatures) > 0:
                self.signatures = []
                for signature in binary.signatures:
                    extra_certs = []

                    signature_dict = {
                        "version": signature.version,
                        "algorithm": signature.digest_algorithm.name,
                        "signers": [],
                        "certificates": [],
                        "content_info": {
                            "algorithm": signature.content_info.digest_algorithm.name,
                            "digest": signature.content_info.digest.hex(),
                            "content_type": signature.content_info.content_type,
                        },
                        "check": signature.check().name(),
                    }

                    def recurse_cert(issuer):
                        issuer_cert = signature.find_crt_subject(issuer)
                        if issuer_cert is None or issuer_cert.subject == issuer_cert.issuer:
                            return
                        recurse_cert(issuer_cert.issuer)
                        if issuer_cert.is_trusted_by(trusted_certs + extra_certs) == lief.PE.x509.VERIFICATION_FLAGS.OK:
                            extra_certs.append(issuer_cert)

                    for signer in signature.signers:
                        recurse_cert(signer.cert.issuer)
                        signer_dict = {
                            "version": signer.version,
                            "issuer": signer.issuer,
                            "serial_number": signer.serial_number.hex(),
                            "encryption_algorithm": signer.encryption_algorithm.name,
                            "digest_algorithm": signer.digest_algorithm.name,
                            "encrypted_digest": signer.encrypted_digest.hex(),
                            "cert": extract_cert_info(signer.cert, trusted_certs + extra_certs),
                            "authenticated_attributes": [
                                # We could keep parsing each type of attribute
                                attribute.type.name
                                for attribute in signer.authenticated_attributes
                            ],
                            "unauthenticated_attributes": [
                                # We could keep parsing each type of attribute
                                attribute.type.name
                                for attribute in signer.unauthenticated_attributes
                            ],
                        }
                        signature_dict["signers"].append(signer_dict)

                    for certificate in signature.certificates:
                        if certificate.is_trusted_by(trusted_certs + extra_certs) != lief.PE.x509.VERIFICATION_FLAGS.OK:
                            recurse_cert(certificate.issuer)

                        signature_dict["certificates"].append(
                            extract_cert_info(certificate, trusted_certs + extra_certs)
                        )

                    self.signatures.append(signature_dict)

        if binary.has_tls:
            if binary.tls.has_section:
                self.tls = {"associated section": binary.tls.section.name}
            elif binary.tls.has_data_directory:
                if binary.tls.directory.has_section:
                    self.tls = {"associated section": binary.tls.directory.section.name}

        # print(binary.imagebase) # Doesn't work as documented?
        self.position_independent = binary.is_pie
        self.is_reproducible_build = binary.is_reproducible_build
        self.overlay = bytearray(binary.overlay).hex()
        self.size_of_headers = binary.sizeof_headers
        self.virtual_size = binary.virtual_size
        if len(binary.symbols) > 0:
            self.symbols = [symbol.name for symbol in binary.symbols]

    def get_node_data(self, node):
        data = {}
        if isinstance(node, lief.PE.ResourceDirectory):
            data["characteristics"] = node.characteristics
            data["num_childs"] = len(node.childs)
            data["depth"] = node.depth
            if node.has_name:
                data["name"] = node.name
            data["id"] = node.id
            if node.depth == 1:
                data["resource_type"] = lief.PE.RESOURCE_TYPES(node.id).name
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
                    data["childs"].append(self.get_node_data(child))
        elif isinstance(node, lief.PE.ResourceData):
            # We could go deeper and figure out which type of resource it is, to get more information.
            data["num_child"] = len(node.childs)
            data["code_page"] = node.code_page
            # data["content"] = node.content
            data["depth"] = node.depth
            if node.has_name:
                data["name"] = node.name
            data["id"] = node.id
            data["is_data"] = node.is_data
            data["is_directory"] = node.is_directory
            data["offset"] = node.offset
            data["reserved"] = node.reserved
        else:
            raise Exception("Binary with unknown ResourceNode", self.name)

        return data
