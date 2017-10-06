#!/usr/bin/env python3

import sys
import antlr4
from parser.PHPLexer import PHPLexer
from parser.PHPParser import PHPParser
from parser.PHPParserListener import PHPParserListener

class PhpPrinter(PHPParserListener):
    def enterHtmlElement(self, ctx):
        print("Entering HTML element", ctx)
    def enterPhpBlock(self, ctx):
        print("Entering PHP block", ctx)
    def enterExpressionStatement(self, ctx):
        print("Entering expression", ctx)
    def enterEchoStatement(self, ctx):
        print("Entering echo", ctx)
    def enterFunctionCall(self, ctx):
        print("Entering function call", ctx)

def main(argv):
    lexer = PHPLexer(antlr4.FileStream(argv[1]))
    stream = antlr4.CommonTokenStream(lexer)
    parser = PHPParser(stream)

    tree = parser.htmlElementOrPhpBlock()

    printer = PhpPrinter()
    walker = antlr4.ParseTreeWalker()
    walker.walk(printer, tree)

if __name__ == '__main__':
    main(sys.argv)
