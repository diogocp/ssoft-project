#!/usr/bin/env python3

import sys
import json


Tainted = True
Untainted = False


class SecurityLevel:
    def __init__(self, tainted, endorsers=None):
        self.tainted = tainted
        self.endorsers = endorsers if endorsers is not None else []

    def __eq__(self, other):
        return NotImplemented

    def __bool__(self):
        return NotImplemented

    def __or__(self, other):
        return NotImplemented

    def __add__(self, other):
        tainted = self.tainted or other.tainted
        if tainted:
            return SecurityLevel(Tainted)
        else:
            return SecurityLevel(Untainted, self.endorsers + other.endorsers)

    def __radd__(self, other):
        if other == 0:
            # This is needed to support the sum function
            return self
        else:
            return NotImplemented

    def __repr__(self):
        return "(%s, %s)" % ("Tainted" if self.tainted else "Untainted", repr(self.endorsers))


class SecurityEnvironment:
    def __init__(self, pattern):
        self.tainted = False
        self.definitions = {}
        self.endorsers = pattern['endorsers']
        self.sinks = pattern['sinks']

        for src in pattern['sources']:
            self.taint(src)

    def is_tainted(self, name, offset=None):
        if offset is not None:
            fullname = "%s[%s]" % (name, offset)
            if fullname in self.definitions:
                return self.definitions[fullname]

        try:
            return self.definitions[name]
        except KeyError:
            return SecurityLevel(Untainted)

    def taint(self, name, offset=None):
        # When tainting any part of an array, we must taint the whole
        # array, to prevent leaks through offset aliases. For example,
        # 'A', "A", "\x41" and "\101" refer to the same offset.
        self.definitions = {k: v for k, v in self.definitions.items()
                            if not k.startswith(name + "[")}
        self.definitions[name] = SecurityLevel(Tainted, [])

    def untaint(self, name, offset=None, endorsers=None):
        if offset is not None:
            name = "%s[%s]" % (name, offset)

        self.definitions[name] = SecurityLevel(Untainted, endorsers)

    def get_active_endorsers(self):
        return set(endorser for d in self.definitions.values() for endorser in d.endorsers)


def main(argv):
    if len(argv) > 2:
        print("Usage:", argv[0], "[FILENAME]", file=sys.stderr)
        return 2
    if len(argv) == 2:
        with open(argv[1]) as f:
            ast = json.load(f)
            filename = "[" + argv[1] + "] "
    else:
        try:
            ast = json.load(sys.stdin)
            filename = ""
        except KeyboardInterrupt:
            return 130

    patterns = read_patterns("patterns.txt")

    vulnerabilities = 0
    for pattern in patterns:
        env = SecurityEnvironment(pattern)
        try:
            parse(ast, env)
        except AssertionError as e:
            vulnerabilities += 1
            print("%s%s: %s." % (filename, pattern['name'], str(e)), file=sys.stderr)
        except KeyboardInterrupt:
            return 130
        else:
            endorsers = env.get_active_endorsers()
            if len(endorsers) == 0:
                pass  # TODO enable output spam...
                #print("%s%s: No vulnerabilities found." % (filename, pattern['name']), file=sys.stderr)
            else:
                # If a sanitization function was used to untaint a variable, we need to display it
                print("%s%s: No vulnerabilities found. Endorsers: %s" % (filename, pattern['name'],
                                                                         ", ".join(endorsers)), file=sys.stderr)

    return 0 if vulnerabilities == 0 else 1


def parse(s, env):
    handlers = {
        'assign': parse_assign,
        'bin': lambda x, env: parse(x['left'], env) + parse(x['right'], env),
        'call': parse_call,
        'echo': parse_construct,
        'print': parse_construct,
        'exit': parse_construct,  # die also gets parsed as exit
        'if': parse_if,
        'while': parse_while,
        'program': parse_block,
        'block': parse_block,
        'variable': lambda x, env: env.is_tainted(x['name']),
        'offsetlookup': parse_offsetlookup,
        'encapsed': parse_encapsed,
        'string': parse_literal,
        'number': parse_literal,
        'boolean': parse_literal,
        'constref': parse_literal,  # TODO: we many need to taint constants too
    }

    handler = handlers[s['kind']]

    return handler(s, env)


def parse_if(s, env):
    parse(s['body'], env)
    if s['alternate'] is not None:
        parse(s['alternate'], env)


def parse_while(s, env):
    parse(s['body'], env)


def parse_block(s, env):
    for child in s['children']:
        parse(child, env)


def parse_offsetlookup(s, env):
    if s['what']['kind'] == "variable":
        return env.is_tainted(s['what']['name'], offset_to_string(s['offset']))
    else:
        return parse(s['what'], env)


def parse_assign(s, env):
    kind = s['left']['kind']
    if kind == "variable":
        name = s['left']['name']
        offset = None
    elif kind == "offsetlookup":
        name = s['left']['what']['name']
        offset = offset_to_string(s['left']['offset'])
    else:
        raise NotImplementedError("assignment to kind %s" % kind)

    if s['operator'] == "=":
        right = parse(s['right'], env)
        if right.tainted:
            env.taint(name, offset)
        else:
            env.untaint(name, offset, right.endorsers)
    else:
        # The other assignment operators (+=, -=, *=, etc.)
        # combine the taintedness of the left and right sides
        left = parse(s['left'], env)
        right = parse(s['right'], env)
        if left.tainted or right.tainted:
            env.taint(name, offset)
        else:
            env.untaint(name, offset, left.endorsers + right.endorsers)


def parse_call(s, env):
    arguments = sum(parse(arg, env) for arg in s['arguments'])
    if arguments.tainted is Untainted:
        # All arguments safe; assume functions don't make them dangerous
        # TODO: we could check if the function is a sensitive _source_
        return arguments

    what = s['what']
    if what['kind'] != "identifier":
        raise NotImplementedError

    if what['name'] in env.endorsers:
        # Endorsers make everything safe
        return SecurityLevel(Untainted, [what['name']])

    if what['name'] not in env.sinks:
        # Not a sensitive sink; continue but assume that the return value is unsafe
        return SecurityLevel(Tainted)

    # If we reach this point, we have an dangerous argument going into a sensitive sink
    raise AssertionError("found '%s' call with unsafe arguments" % what['name'])


def parse_construct(s, env):
    # We assume any value that these constructs may return is untainted
    if s['kind'] not in env.sinks:
        return SecurityLevel(Untainted)

    # arguments may be either an array (when the construct accepts more than one),
    # or an object, when the construct takes a single argument. In the case of exit,
    # the arguments are in an object named status...
    if s['kind'] == "echo":
        arguments = s['arguments']
    elif s['kind'] == "print":
        arguments = [s['arguments']]
    elif s['kind'] == "exit":
        arguments = [s['status']]
    else:
        raise NotImplementedError("language construct '%s' not implemented" % s['kind'])

    if sum(parse(arg, env) for arg in arguments).tainted:
        raise AssertionError("found '%s' with unsafe arguments" % s['kind'])

    return SecurityLevel(Untainted)


def parse_encapsed(s, env):
    return sum(parse(elem, env) for elem in s['value'])


def parse_literal(s, env):
    return SecurityLevel(Untainted)


def offset_to_string(s):
    try:
        kind = s['kind']
        value = s['value']

        if kind in ["number", "boolean"]:
            return value

        if kind == "string":
            if s['isDoubleQuote']:
                return '"%s"' % value
            else:
                return "'%s'" % value

        return None
    except KeyError:
        return None


def read_patterns(filename):
    with open(filename) as f:
        lines = f.readlines()

    # Ignore empty lines
    lines = map(str.strip, lines)
    lines = filter(len, lines)

    patterns = []
    try:
        while True:
            name = next(lines)
            sources = next(lines).split(',')
            endorsers = next(lines).split(',')
            sinks = next(lines).split(',')

            # Remove $ from the beginning of variable names
            sources = [s[1:] if s.startswith("$") else s for s in sources]

            patterns.append({'name': name, 'sources': sources, 'endorsers': endorsers, 'sinks': sinks})
    except StopIteration:
        pass

    return patterns


if __name__ == '__main__':
    sys.exit(main(sys.argv))
