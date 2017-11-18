#!/usr/bin/env python3

import sys
import json
import copy


Tainted = True
Untainted = False


class SecurityLevel:
    def __init__(self, tainted, endorsers=None):
        self.tainted = tainted
        self.endorsers = endorsers if endorsers is not None else set()

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
            return SecurityLevel(Untainted, self.endorsers | other.endorsers)

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
        self.endorsers = set(pattern['endorsers'])
        self.sinks = set(pattern['sinks'])
        self.active_endorsers = set()

        for src in pattern['sources']:
            self.taint(src)

    def merge(self, other):
        self.tainted |= other.tainted
        self.definitions.update({k: v for k, v in other.definitions.items() if v.tainted})
        self.endorsers &= other.sinks
        self.sinks |= other.sinks

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
        self.definitions[name] = SecurityLevel(Tainted)

    def untaint(self, name, offset=None, endorsers=None):
        if offset is not None:
            name = "%s[%s]" % (name, offset)

        self.definitions[name] = SecurityLevel(Untainted, endorsers)


class SecurityException(Exception):
    """Exception raised when tainted arguments are passed to a sensitive sink.

    Attributes:
        expression -- input expression in which the error occurred
    """

    def __init__(self, sink):
        self.sink = sink


def main(argv):
    if len(argv) > 2:
        print("Usage:", argv[0], "[FILENAME]", file=sys.stderr)
        return 2
    if len(argv) == 2:
        with open(argv[1]) as f:
            ast = json.load(f)
    else:
        try:
            ast = json.load(sys.stdin)
        except KeyboardInterrupt:
            return 130

    patterns = read_patterns("patterns.txt")

    vulnerabilities = 0
    for pattern in patterns:
        env = SecurityEnvironment(pattern)

        try:
            parse(ast, env)
        except SecurityException:
            vulnerabilities += 1
            print("WARNING: found possible vulnerability:", pattern['name'])
        except KeyboardInterrupt:
            return 130
        else:
            if len(env.active_endorsers) > 0:
                # If any endorsed variables were passed to sensitive sinks,
                # we print the names of the endorsers used.
                endorsers = ", ".join(env.active_endorsers)
                print("No %s vulnerabilities found due to endorsers: %s" % (pattern['name'], endorsers))

    if vulnerabilities == 0:
        print("No vulnerabilities found.")
        return 0
    else:
        return 1


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
    # Tests can have side effects, so we must always parse them
    parse(s['test'], env)

    # Evaluate the if body in a copy of the environment
    env_if = copy.deepcopy(env)
    parse(s['body'], env_if)

    # If there is an else, evaluate it too, but on the
    # original environment, since we only go into the
    # alternate if we don't go into the if body
    if s['alternate'] is not None:
        parse(s['alternate'], env)

    # Finally, merge both environments (if and alternate)
    env.merge(env_if)


def parse_while(s, env):
    parse(s['test'], env)

    env_loop = copy.deepcopy(env)
    for _ in s['body']['children']:
        parse(s['body'], env_loop)
        parse(s['test'], env_loop)
        env.merge(env_loop)


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
    what = s['what']
    if what['kind'] != "identifier":
        raise NotImplementedError

    if what['name'] in env.endorsers:
        # Endorsers always return untainted.
        # We assume they don't have side effects.
        return SecurityLevel(Untainted, {what['name']})

    # Check if any argument is tainted
    arguments = sum(parse(arg, env) for arg in s['arguments'])

    if what['name'] not in env.sinks:
        # Not a sensitive sink; continue assuming that the
        # return value is tainted if any argument is tainted.
        return arguments

    if arguments.tainted:
        # Tainted argument passed to sensitive sink!
        raise SecurityException(what['name'])
    else:
        # Untainted argument passed to sensitive sink.
        # Mark endorsers as active.
        env.active_endorsers |= arguments.endorsers
        return arguments


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
        raise SecurityException(s['kind'])

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
