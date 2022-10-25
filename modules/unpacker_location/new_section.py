def add_unpacker(pe, unpacker_code):
    section = pe.add_section(b'.new', unpacker_code)
    return section.VirtualAddress