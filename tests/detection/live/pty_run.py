#!/usr/bin/env python3
"""pty_run.py - run a command on a new pseudo terminal and answer its prompts.

LIVE TESTS ONLY (tests/detection/live/run.sh, on a GitHub runner). Logins
that ask for a password read it from a terminal, never from a pipe: ssh
with a password, su, and login (the console's door).

Usage: pty_run.py [--answer-file FILE] [--then TEXT] [--timeout N] -- COMMAND [ARG...]
  --answer-file FILE  lines "PROMPT<TAB>TEXT". When the output so far holds
                      PROMPT (case does not matter), TEXT and Enter are
                      typed, each line once, in the order of the file. The
                      file keeps test passwords off the command line.
  --then TEXT         typed 2 s after the last answer (for example: exit)
  --timeout N         seconds (default 30): then the command is killed
Prints what the command wrote. Exit code: the command's own, 124 after a
timeout.
"""
import argparse
import os
import pty
import select
import signal
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--answer-file", default="")
    ap.add_argument("--then", default="")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("command", nargs="+")
    a = ap.parse_args()
    answers = []
    if a.answer_file:
        with open(a.answer_file, encoding="utf-8") as fh:
            for line in fh:
                if "\t" in line:
                    prompt, text = line.rstrip("\n").split("\t", 1)
                    answers.append((prompt.lower(), text))

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(a.command[0], a.command)
    seen = b""
    mark = 0
    end = time.monotonic() + a.timeout
    then_at = time.monotonic() + 2 if (a.then and not answers) else None
    rc = 124
    while True:
        left = end - time.monotonic()
        if left <= 0:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            break
        ready, _, _ = select.select([fd], [], [], min(left, 0.2))
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                chunk = b""
            if not chunk:
                break
            seen += chunk
        if answers and answers[0][0].encode() in seen[mark:].lower():
            _prompt, text = answers.pop(0)
            mark = len(seen)
            time.sleep(0.3)
            os.write(fd, text.encode() + b"\n")
            if not answers and a.then:
                then_at = time.monotonic() + 2
        elif then_at and time.monotonic() >= then_at:
            os.write(fd, a.then.encode() + b"\n")
            then_at = None
    try:
        _, status = os.waitpid(pid, 0)
        if rc == 124 and time.monotonic() < end:
            rc = os.waitstatus_to_exitcode(status)
    except OSError:
        pass
    sys.stdout.write(seen.decode("utf-8", "replace"))
    return rc if rc >= 0 else 128 - rc


if __name__ == "__main__":
    sys.exit(main())
