#!/usr/bin/env python3

import sys
import json

def main(argv):
    input_file = argv[1]
    with open(input_file, 'r') as f:
        raw_ast = json.load(f)
    
    print(raw_ast)


if __name__ == '__main__':
    main(sys.argv)
