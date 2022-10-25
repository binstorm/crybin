def inject_entrypoint(pe, entry_point):
    pe.pe.OPTIONAL_HEADER.AddressOfEntryPoint = entry_point