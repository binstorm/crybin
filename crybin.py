import pefile
import importlib
import os

class CrySection:
    def _find_section(self, section_name):
        for section in self.pe.sections:
            if section.Name.decode('utf-8').strip('\x00') == section_name:
                return section
        return None
    
    def __init__(self, pe, section_name: str):
        self.pe: pefile.PE = pe
        self.section = self._find_section(section_name)
        if self.section is None:
            raise Exception('Section not found')

    @property
    def data(self):
        return bytearray(self.section.get_data())

    @data.setter
    def data(self, data):
        self.pe.set_bytes_at_rva(self.section.VirtualAddress, bytes(data))

class CryPE:
    def load_encryption_modules(self):
        self.encryption_modules = {}
        for module in os.listdir('encryption'):
            if module.endswith('.py'):
                module_name = module.rstrip('.py')
                self.encryption_modules[module_name] = importlib.import_module(f'encryption.{module_name}')

    def __init__(self, path):
        self.pe = pefile.PE(path)
        self.load_encryption_modules()

    def encrypt_section(self, section_name, encryption_module, **params):
        section = CrySection(self.pe, section_name)
        encryption_module = self.encryption_modules.get(encryption_module)
        if encryption_module is None:
            raise Exception(f'Encryption module {encryption_module} not found')
        
        section.data = encryption_module.encrypt(section.data, **params)
    
    def save(self, path):
        self.pe.write(path)
