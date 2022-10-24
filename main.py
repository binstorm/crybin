import argparse
import random
from crybin import CryPE


def main():
    parser = argparse.ArgumentParser(description='CryBin - Binary Manipulation Framework')
    parser.add_argument('encryption_module', help='Encryption module')
    parser.add_argument('input', help='Input binary')
    parser.add_argument('output', help='Output path')

    # Optional encryption key
    parser.add_argument('--key', type=int, default=random.randint(0, 255), help='Encryption key')
    
    args = parser.parse_args()

    pe = CryPE(args.input)
    pe.encrypt_section('.text', args.encryption_module, key=args.key)
    pe.save(args.output)
    print(f'File saved to {args.output}')

if __name__ == '__main__':
    main()
