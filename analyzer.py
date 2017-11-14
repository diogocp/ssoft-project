#!/usr/bin/env python3

import sys
import json
import warnings


filename = ""
pattern = {}
definitions = {}


def main(argv):
    global filename
    global pattern

    if len(argv) > 2:
        print("Usage:", argv[0], "[FILENAME]", file=sys.stderr)
        return 2
    if len(argv) == 2:
        with open(argv[1]) as f:
            filename = "[" + argv[1] + "] "
            ast = json.load(f)
    else:
        try:
            ast = json.load(sys.stdin)
        except KeyboardInterrupt:
            return 130

    patterns = read_patterns("patterns.txt")

    vulnerabilities = 0
    for p in patterns:
        pattern = p
        definitions.clear()

        for src in p['sources']:
            definitions[src] = True

        try:
            parse(ast)
        except AssertionError as e:
            vulnerabilities += 1
            print("%s%s: %s." % (filename, p['name'], str(e)), file=sys.stderr)
        except KeyboardInterrupt:
            return 130

    if vulnerabilities == 0:
        print("%sNo vulnerabilities found." % filename, file=sys.stderr)
        return 0
    else:
        return 1


def parse(s):
    handlers = {
        'assign': parse_assign,
        'bin': lambda x: parse(x['left']) or parse(x['right']),
        'call': parse_call,
        'echo': parse_construct,
        'print': parse_construct,
        'exit': parse_construct,  # die also gets parsed as exit
        'program': parse_program,
        'variable': lambda x: definitions.get(x['name']),
        'offsetlookup': lambda x: parse(x['what']),
        'encapsed': lambda x: any(map(parse, x['value'])),
        'string': lambda x: False,
        'number': lambda x: False,
        'boolean': lambda x: False
    }
    try:
        handler = handlers[s['kind']]
    except KeyError:
        warnings.warn("no handler for nodes of kind '%s'" % s['kind'])
        return False
    return handler(s)


def parse_program(s):
    for child in s['children']:
        parse(child)


def parse_assign(s):
    left = s['left']
    right = s['right']

    # TODO: see what else could be here and how to handle it
    # += -= *= /= %= .= &= |= ^= <<= >>=
    if s['operator'] != "=":
        raise NotImplementedError

    # TODO: handle assignments to arrays (e.g. _GET['x'] = 42)
    if left['kind'] != "variable":
        raise NotImplementedError
    name = left['name']

    definitions[name] = parse(right)


def parse_call(s):
    if not any(parse(arg) for arg in s['arguments']):
        # All arguments safe; assume functions don't make them dangerous
        # TODO: we could check if the function is a sensitive _source_
        return False

    what = s['what']
    if what['kind'] != "identifier":
        raise NotImplementedError

    if what['name'] in pattern['downgraders']:
        # Downgraders make everything safe
        return False

    if what['name'] not in pattern['sinks']:
        # Not a sensitive sink; continue but assume that the return value is unsafe
        return True

    # If we reach this point, we have an dangerous argument going into a sensitive sink
    raise AssertionError("found '%s' call with unsafe arguments" % what['name'])


def parse_construct(s):
    if s['kind'] not in pattern['sinks']:
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

    if any(parse(arg) for arg in arguments):
        raise AssertionError("found '%s' with unsafe arguments" % s['kind'])

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
            downgraders = next(lines).split(',')
            sinks = next(lines).split(',')

            # Remove $ from the beginning of variable names
            sources = [s[1:] if s.startswith("$") else s for s in sources]

            patterns.append({'name': name, 'sources': sources, 'downgraders': downgraders, 'sinks': sinks})
    except StopIteration:
        pass

    return patterns


def showwarning(message, *unused, file=sys.stderr):
    print("%sWarning:" % filename, message, file=file)
warnings.showwarning = showwarning


if __name__ == '__main__':
    sys.exit(main(sys.argv))
