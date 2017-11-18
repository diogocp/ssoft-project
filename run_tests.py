#!/usr/bin/env python3

import io
import sys
import analyzer


class Slice:
    def __init__(self, filename, pattern=None, endorsers=None):
        self.filename = filename
        self.pattern = pattern
        self.endorsers = endorsers


def main():
    slices = [
        Slice("slices/slice1.json", "SQL injection"),
        Slice("slices/slice2.json", "SQL injection"),
        Slice("slices/slice3.json", "SQL injection"),
        Slice("slices/slice4.json", "SQL injection"),
        Slice("slices/slice5.json", "SQL injection"),
        Slice("slices/slice6.json", "Cross site scripting"),
        Slice("slices/slice7.json", "SQL injection"),
        Slice("slices/slice9.json", "SQL injection"),
        Slice("slices/slice10.json", "SQL injection"),
        Slice("slices/slice11.json", "SQL injection")
    ]

    original_stdout = sys.stdout
    failures = 0
    for s in slices:
        with io.StringIO() as sys.stdout:
            analyzer.main([None, s.filename])

            if check_output(s, sys.stdout.getvalue()):
                print("[ OK ]", s.filename, file=original_stdout)
            else:
                failures += 1
                print("[FAIL]", s.filename, file=original_stdout)
    sys.stdout = original_stdout

    return 0 if failures == 0 else 1


def check_output(s, output):
    # Not vulnerable
    if s.pattern is None:
        return output.startswith("No vulnerabilities")

    # vulnerable
    if s.endorsers is None:
        return output.startswith("WARNING: found possible vulnerability: " + s.pattern)

    # Endorsed
    return output.startswith("No %s vulnerability due to endorsers: %s" % (s.pattern, s.endorsers))


if __name__ == '__main__':
    sys.exit(main())
