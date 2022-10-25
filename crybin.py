import pefile
import importlib
import os

from utils import align

class CrySection:
    def _find_section(self, section_name: str):
        for section in self.pe.sections:
            if section.Name.decode('utf-8').strip('\x00') == section_name:
                return section
        return None
    
    def __init__(self, pe: pefile.PE, section_name: str, new_section: bool=False):
        self.pe = pe
        if new_section:
            self.section = self.pe.sections[-1]
            self.section.Name = section_name
        else:
            self.section = self._find_section(section_name)
            if self.section is None:
                raise Exception(f'Section "{section_name}" not found')

    @property
    def data(self):
        return bytearray(self.section.get_data())

    @data.setter
    def data(self, data: bytes):
        self.section.Misc_VirtualSize = len(data)
        self.section.SizeOfRawData = align(len(data), self.pe.OPTIONAL_HEADER.FileAlignment)
        self.pe.set_bytes_at_rva(self.section.VirtualAddress, bytes(data))

    @property
    def VirtualAddress(self):
        return self.section.VirtualAddress
    
    @VirtualAddress.setter
    def VirtualAddress(self, value: int):
        self.section.VirtualAddress = value

class CryPE:
    @staticmethod
    def load_modules(module_type: str):
        modules_path = os.path.join(os.path.dirname(__file__), 'modules', module_type)
        modules = {}
        for module in os.listdir(modules_path):
            if module.endswith('.py'):
                module_name = module.rstrip('.py')
                module = importlib.import_module(f'modules.{module_type}.{module_name}')
                modules[module_name] = module
    
        return modules

    def __init__(self, path: str):
        self.pe = pefile.PE(path)
        self.encryption_modules = CryPE.load_modules('encryption')
        self.unpacker_location_modules = CryPE.load_modules('unpacker_location')
        self.unpacker_entry_modules = CryPE.load_modules('unpacker_entry')
        self.encryption = None

    def encrypt_section(self, section_name: str, encryption_module: str, **params):
        section = CrySection(self.pe, section_name)
        encryption_module = self.encryption_modules.get(encryption_module)
        if encryption_module is None:
            raise Exception(f'Encryption module "{encryption_module}" not found')
        
        section.data = encryption_module.encrypt(section.data, **params)

    def add_section(self, name: str, data: bytes):
        section = CrySection(self.pe, name, new_section=True)
        section.data = data
        self.pe.OPTIONAL_HEADER.SizeOfImage += section.section.SizeOfRawData
        self.pe.FILE_HEADER.NumberOfSections += 1
        return section
    
    def add_unpacker(self, encryption_module: str, unpacker_location: str, unpacker_entry: str, **params):
        # Load modules
        encryption_module = self.encryption_modules.get(encryption_module)
        if encryption_module is None:
            raise Exception(f'Encryption module "{encryption_module}" not found')

        unpacker_location_module = self.unpacker_location_modules.get(unpacker_location)
        if unpacker_location_module is None:
            raise Exception(f'Unpacker location module "{unpacker_location}" not found')

        unpacker_entry_module = self.unpacker_entry_modules.get(unpacker_entry)
        if unpacker_entry_module is None:
            raise Exception(f'Unpacker entry module "{unpacker_entry}" not found')

        # Generate unpacker
        unpacker_code = encryption_module.generate_unpacker(**params)

        # Add unpacker to binary
        entry_point = unpacker_location_module.add_unpacker(self, unpacker_code)

        # Inject entrypoint using specified method
        unpacker_entry_module.inject_entrypoint(self, entry_point)
    
    def save(self, path):
        self.pe.write(path)
