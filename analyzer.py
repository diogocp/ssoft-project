#!/usr/bin/env python3

import sys
import json


class SecurityEnvironment:
    def __init__(self, pattern):
        self.tainted = False
        self.definitions = {}
        self.endorsers = pattern['endorsers']
        self.sinks = pattern['sinks']

        for src in pattern['sources']:
            self.taint(src)

    def is_tainted(self, name):
        try:
            return self.definitions[name][0]
        except KeyError:
            return False

    def taint(self, name):
        self.definitions[name] = (True, None)

    def untaint(self, name, endorser):
        self.definitions[name] = (False, endorser)

    def get_active_endorsers(self):
        return [d[1] for d in self.definitions if not d[0] and d[1] is not None]


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
        try:
            env = SecurityEnvironment(pattern)
            parse(ast, env)
        except AssertionError as e:
            vulnerabilities += 1
            print("%s%s: %s." % (filename, pattern['name'], str(e)), file=sys.stderr)
        except KeyboardInterrupt:
            return 130
        else:
            endorsers = env.get_active_endorsers()
            # If a sanitization function was used to untaint a variable, we need to display it
            endorsers = "." if len(endorsers) == 0 else "; endorsed by " + ", ".join(endorsers)
            print("%s%s: No vulnerabilities found%s" % (filename, pattern['name'], endorsers), file=sys.stderr)

    return 0 if vulnerabilities == 0 else 1


def parse(s, env):
    handlers = {
        'assign': parse_assign,
        'bin': lambda x, env: parse(x['left'], env) or parse(x['right'], env),
        'call': parse_call,
        'echo': parse_construct,
        'print': parse_construct,
        'exit': parse_construct,  # die also gets parsed as exit
        'if': parse_if,
        'while': parse_while,
        'program': parse_block,
        'block': parse_block,
        'variable': lambda x, env: env.is_tainted(x['name']),
        'offsetlookup': lambda x, env: parse(x['what'], env),
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


def parse_assign(s, env):
    left = s['left']
    right = s['right']

    # TODO: see what else could be here and how to handle it
    # += -= *= /= %= .= &= |= ^= <<= >>=
    if s['operator'] != "=":
        raise NotImplementedError

    # TODO: handle assignments to arrays (e.g. _GET['x'] = 42)
    if left['kind'] != "variable":
        raise NotImplementedError

    if parse(right, env):
        env.taint(left['name'])


def parse_call(s, env):
    if not any(parse(arg, env) for arg in s['arguments']):
        # All arguments safe; assume functions don't make them dangerous
        # TODO: we could check if the function is a sensitive _source_
        return False

    what = s['what']
    if what['kind'] != "identifier":
        raise NotImplementedError

    if what['name'] in env.endorsers:
        # Endorsers make everything safe
        return False

    if what['name'] not in env.sinks:
        # Not a sensitive sink; continue but assume that the return value is unsafe
        return True

    # If we reach this point, we have an dangerous argument going into a sensitive sink
    raise AssertionError("found '%s' call with unsafe arguments" % what['name'])


def parse_construct(s, env):
    if s['kind'] not in env.sinks:
        return False

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

    if any(parse(arg, env) for arg in arguments):
        raise AssertionError("found '%s' with unsafe arguments" % s['kind'])

    return False


def parse_encapsed(s, env):
    for elem in s['value']:
        if parse(elem, env):
            return True

    return False


def parse_literal(s, env):
    return False


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
