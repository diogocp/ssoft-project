#!/usr/bin/env python3

import sys
from antlr4 import *
from parser.PHPLexer import PHPLexer
from parser.PHPParser import PHPParser

def main(argv):
    input = FileStream(argv[1])
    lexer = PHPLexer(input)
    stream = CommonTokenStream(lexer)
    parser = PHPParser(stream)
    tree = parser.phpBlock()

if __name__ == '__main__':
    main(sys.argv)
