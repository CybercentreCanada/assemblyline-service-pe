import lief


def is_mapped(pe: lief.PE.Binary, file_size_bytes: int) -> bool:
    # This isn't an exact because it isn't possible to accurately determine
    # the address where the PE was loaded in memory before getting dumped.

    # We're just hoping to align the sections to where we could perform a better static analysis.
    # Additional check added to filter out unmapped files
    if pe.optional_header.checksum == pe.optional_header.computed_checksum:
        return False

    # Compute the anticipated static
    virtual_size = pe.optional_header.sizeof_image
    header_size = pe.optional_header.sizeof_headers
    overlay_size = len(pe.overlay)
    section_size = 0
    for section in pe.sections:
        section_size += section.size

    anticipated_size = overlay_size + section_size + header_size
    static_difference = abs(anticipated_size - file_size_bytes)
    virtual_difference = abs(virtual_size - file_size_bytes)
    if static_difference < virtual_difference:
        return False

    text_section = pe.get_section(".text")
    if text_section is None:
        return False
    difference: int = text_section.virtual_address - text_section.offset
    if not difference:
        return False
    # Order doesn't matter since are looking for all zeros.
    numerical_equivalent = int.from_bytes(text_section.content[0:difference], byteorder="little")

    # Last check performed, hopefully at this point we filtered our the false positives
    if not numerical_equivalent:
        return True


def unmap(pe: lief.PE.Binary, in_data):
    """
    It is currently performing better when we don't try modifying the base image
    However, it will break when samples have absolute jump instructions in their code.
    """

    # Fix alignment
    pe.optional_header.file_alignment = pe.optional_header.section_alignment

    # Fix sections
    alignment = pe.optional_header.section_alignment
    for section in pe.sections:
        section.pointerto_raw_data = section.virtual_address
        new_size = section.virtual_size
        if new_size % alignment != 0:
            new_size = alignment * (1 + new_size // alignment)
        section.sizeof_raw_data = new_size

    """Once we have realigned the PE file - We will build the unmapped 'equivalent'"""
    builder = lief.PE.Builder(pe)
    builder.build()
    out_data = bytes(builder.get_build())
    headers = out_data[:0x1000] + in_data[0x1000:]

    unmapped = lief.parse(raw=headers)
    unmapped.remove_all_relocations()
    builder = lief.PE.Builder(unmapped).build_dos_stub(False)
    builder.build()
    out_data = bytes(builder.get_build())
    # Keep the DOS STUB from the original file.
    return out_data[:0x40] + in_data[0x40:0x80] + out_data[0x80:]


if __name__ == "__main__":
    import argparse
    import os
    from pathlib import Path

    parser = argparse.ArgumentParser(prog="Pe Unmapper", description="Unmaps a PE file")
    parser.add_argument("mapped_filename")
    args = parser.parse_args()
    in_data = Path(args.mapped_filename).read_bytes()
    pe_file = lief.parse(raw=in_data)
    if is_mapped(pe_file, os.path.getsize(args.mapped_filename)):
        out_data = unmap(pe_file, in_data)
        Path(f"{args.mapped_filename}_unmapped").write_bytes(out_data)
