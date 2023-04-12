import lief


def is_mapped(pe: lief.PE.Binary) -> bool:
    """
    [To recognize if a file is mapped]
    We check to see whether the .text section starts at
        a) Its raw offset
        b) Its virtual offset

    This can be done by verifying if from the section_content[raw_address:virtual_address] is all zeros.
    If it is all zeros, we can conclude that it is mapped.
    Additionally, we want to account for files that were potentially unmapped before.
    We can conclude the file is unmapped if the virtual_address == raw_address
    """
    text_section = pe.get_section(".text")
    if text_section is None:
        return False
    difference: int = text_section.virtual_address - text_section.offset
    if not difference:
        return False
    section_content: bytes = text_section.content

    difference_content: bytes = bytes(section_content[0:difference])
    numerical_equivalent = int.from_bytes(difference_content, byteorder="little")
    return not numerical_equivalent


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
    builder = lief.PE.Builder(unmapped)
    builder.build()
    return bytes(builder.get_build())


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(prog="Pe Unmapper", description="Unmaps a PE file")
    parser.add_argument("mapped_filename")
    args = parser.parse_args()
    in_data = Path(args.mapped_filename).read_bytes()
    pe_file = lief.parse(raw=in_data)
    if is_mapped(pe_file):
        out_data = unmap(pe_file, in_data)
        Path(f"{args.mapped_filename}_unmapped").write_bytes(out_data)
