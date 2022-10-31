import argparse
import random
from crybin import CryPE


def main():
    parser = argparse.ArgumentParser(description='CryBin - Binary Manipulation Framework')
    parser.add_argument('--encryption', help='Packer encryption module', default='xor')
    parser.add_argument('--key', type=int, default=random.randint(0, 255), help='Encryption key')    
    parser.add_argument('--unpacker_location', help='Unpacker location', default='new_section')
    parser.add_argument('--unpacker_entry', help='Unpacker entry method', default='modify_entrypoint')
    parser.add_argument('input_file', help='Input binary file')
    parser.add_argument('output_file', help='Output binary file')
    args = parser.parse_args()

    pe = CryPE(args.input_file)
    pe.encrypt_section('.text', args.encryption, key=args.key)
    pe.add_unpacker(args.encryption, args.unpacker_location, args.unpacker_entry, key=args.key)
    print(pe.pe.sections[-1])
    print("FileAlignment", hex(pe.pe.OPTIONAL_HEADER.FileAlignment))
    pe.save(args.output_file)
    print(f'File saved to {args.output_file}')

if __name__ == '__main__':
    main()
