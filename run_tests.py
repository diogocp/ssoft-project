#!/usr/bin/env python3

import io
import re
import sys
import analyzer


class Slice:
    def __init__(self, filename, pattern, endorsers=None):
        self.filename = filename
        self.pattern = pattern
        self.endorsers = endorsers


def main():
    basedir = "slices/"
    fileext = ".json"

    slices = [
        Slice("slice1", "SQL injection"),
        Slice("slice2", "SQL injection"),
        Slice("slice3", "SQL injection"),
        Slice("slice4", "SQL injection"),
        Slice("slice5", "SQL injection"),
        Slice("slice6", "Cross site scripting"),
        Slice("slice7", "SQL injection"),
        Slice("slice9", "SQL injection"),
        Slice("slice10", "SQL injection"),
        Slice("slice11", "SQL injection"),
        Slice("safe_literal", None),
        Slice("dot_equals", "SQL injection"),
        Slice("while_backward_untaint", "SQL injection"),
        Slice("while_untainted_guard", None),
        Slice("untainted_offset", None),
        Slice("trycatch", None),
        Slice("tainted_try", "Cross site scripting"),
        Slice("dowhile", "SQL injection"),
        Slice("for", "SQL injection"),
        Slice("sql_escaped", "SQL injection", "mysql_escape_string"),
    ]

    original_stdout = sys.stdout
    failures = 0
    for s in slices:
        with io.StringIO() as sys.stdout:
            filename = basedir + s.filename + fileext
            analyzer.main([None, filename])

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
    return re.match("No %s .* endorsers: %s" % (s.pattern, s.endorsers), output) is not None


if __name__ == '__main__':
    sys.exit(main())
