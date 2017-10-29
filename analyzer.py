#!/usr/bin/env python3

from enum import Enum
import sys
import json

NodeKind = Enum("NodeKind", 'LITERAL VARIABLE FUNCTION OPERATOR',
                module=__name__)


class Node:
    def __init__(self, label='', kind=NodeKind.VARIABLE):
        if "_last_id" not in Node.__dict__:
            Node._last_id = 0
        else:
            Node._last_id += 1

        self._id = Node._last_id
        self.kind = kind
        self.label = label
        self._inputs = []
        self._outputs = []
        self._graph = None

    def __str__(self):
        # TODO: add more information?
        return '<Node#{}: {}>'.format(self._id, self.label)

    def add_input(self, node):
        self._inputs.append(node)
        node._outputs.append(self)

    def add_output(self, node):
        self._outputs.append(node)
        node._inputs.append(self)

    def to_dot(self, f):
        print('  {} [label={}];'.format(self._id, json.dumps(self.label)),
              file=f)
        for input in self._inputs:
            print("  {} -> {};".format(input._id, self._id), file=f)


class DependencyGraph:
    def __init__(self):
        self.nodes = set()
        self.tainted_nodes = set()
        self.vulnerable_nodes = set()
        self.variables = set()
        self.functions = set()

    def add_node(self, node):
        node._graph = self
        self.nodes.add(node)

    def to_dot(self, f):
        print('digraph {', file=f)
        for node in self.nodes:
            node.to_dot(f)
        print('}', file=f)


def call_debugger():
    import pdb
    pdb.set_trace()


def weird_json_ast_to_graph(ast):
    live_variables = {}
    graph = DependencyGraph()

    def walk_ast(node):
        if node['kind'] == "program":
            for child in node['children']:
                walk_ast(child)
            return

        if node['kind'] == "variable":
            name = '$' + node['name']
            var = live_variables.get(name, None)
            if var:
                return var
            var = Node(label=name)
            live_variables[name] = var
            graph.add_node(var)
            return var

        if node['kind'] == "assign":
            # We need to process the right part first. e.g.:
            #     $a = $a + 1
            # The $a on the right refers to an old node
            left = walk_ast(node['left'])
            right = walk_ast(node['right'])
            assign_node = Node(label='op=', kind=NodeKind.OPERATOR)
            assign_node.add_input(left)
            assign_node.add_input(right)
            graph.add_node(assign_node)

            out_node = Node(label=left.label)
            out_node.add_input(assign_node)
            graph.add_node(out_node)

            # FIXME: this doesn't handle e.g. _GET['batata'] = 3;
            if left.kind == NodeKind.VARIABLE:
                live_variables[left.label] = out_node
            else:
                call_debugger()

            return out_node

        if node['kind'] == 'offsetlookup':
            left = walk_ast(node['what'])
            right = walk_ast(node['offset'])
            out_node = Node(label='op[]', kind=NodeKind.OPERATOR)
            out_node.add_input(left)
            out_node.add_input(right)
            graph.add_node(out_node)
            return out_node

        if node['kind'] == "bin":
            left = walk_ast(node['left'])
            right = walk_ast(node['right'])
            op = 'op{}'.format(node['type'])
            out_node = Node(label=op, kind=NodeKind.OPERATOR)
            out_node.add_input(left)
            out_node.add_input(right)
            graph.add_node(out_node)
            return out_node

        if node['kind'] == 'encapsed':
            inputs = map(walk_ast, node['value'])
            out_node = Node(label='op"$"', kind=NodeKind.OPERATOR)
            for input in inputs:
                out_node.add_input(input)
            graph.add_node(out_node)
            return out_node

        if node['kind'] == 'string':
            label = repr(node['value'])
            out_node = Node(label=label, kind=NodeKind.LITERAL)
            graph.add_node(out_node)
            return out_node

        if node['kind'] == "call":
            inputs = map(walk_ast, node['arguments'])
            op = '{}()'.format(node['what']['name'])
            out_node = Node(label=op, kind=NodeKind.FUNCTION)
            for input in inputs:
                out_node.add_input(input)
            graph.add_node(out_node)
            return out_node

        # TODO: add missing AST types
        call_debugger()

    walk_ast(ast)
    graph.variables = (node for node in graph.nodes
                       if node.kind == NodeKind.VARIABLE)
    graph.functions = (node for node in graph.nodes
                       if node.kind == NodeKind.FUNCTION)
    return graph

def parse_patterns(f):
    blocks = []
    for line in f:
        line = line.strip()
        if line == "" and blocks != [] and blocks[-1] != []:
            blocks.append([])
        elif blocks != []:
            blocks[-1].append(line)
        else:
            blocks = [[line]]

    # TODO: actually parse this
    return blocks

def main(argv):
    input_file = argv[1]
    with open(input_file, 'r') as f:
        raw_ast = json.load(f)

    graph = weird_json_ast_to_graph(raw_ast)
    graph.to_dot(sys.stdout)

    with open('patterns.txt', 'r') as f:
        patterns = parse_patterns(f)


if __name__ == '__main__':
    main(sys.argv)
