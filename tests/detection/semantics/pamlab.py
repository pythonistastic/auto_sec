#!/usr/bin/env python3
"""pamlab.py - open one PAM session through a lab service file, without root.

LAB ONLY (tests/detection/semantics/run.sh). It calls libpam's
pam_start_confdir() (Linux-PAM 1.4.0 and newer), so the service file comes
from a lab folder instead of /etc/pam.d. The service file names the module
under test by its full path, for example the pam_exec.so unpacked from a
pinned libpam-modules .deb. Nothing under /etc is read or written by this
program itself.

Usage:
  pamlab.py --confdir DIR --service NAME --user USER
            [--tty TTY] [--rhost HOST] [--ruser USER] [--libpam PATH] [--no-close]
Prints one JSON line:
  {"start": rc, "open": rc, "close": rc, "open_ms": n, "close_ms": n, "pid": n}
PAM_SUCCESS is 0. open_ms is how long pam_open_session() took. pid is this
program's own: the process that opened the session.
"""
import argparse
import ctypes
import json
import os
import sys
import time

PAM_TTY = 3
PAM_RHOST = 4
PAM_RUSER = 8
PAM_CONV_ERR = 19


class PamMessage(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class PamResponse(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_char_p), ("resp_retcode", ctypes.c_int)]


CONV_FUNC = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(PamMessage)),
    ctypes.POINTER(ctypes.POINTER(PamResponse)), ctypes.c_void_p)


class PamConv(ctypes.Structure):
    _fields_ = [("conv", CONV_FUNC), ("appdata_ptr", ctypes.c_void_p)]


def _conv(_n, _msg, _resp, _data):
    # No module in the lab stack may ask anything.
    return PAM_CONV_ERR


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--confdir", required=True)
    ap.add_argument("--service", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--tty", default="")
    ap.add_argument("--rhost", default="")
    ap.add_argument("--ruser", default="")
    ap.add_argument("--libpam", default="libpam.so.0")
    ap.add_argument("--no-close", action="store_true")
    a = ap.parse_args()

    pam = ctypes.CDLL(a.libpam, use_errno=True)
    pam.pam_start_confdir.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(PamConv),
                                      ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    pam.pam_set_item.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
    pam.pam_open_session.argtypes = [ctypes.c_void_p, ctypes.c_int]
    pam.pam_close_session.argtypes = [ctypes.c_void_p, ctypes.c_int]
    pam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]

    conv = PamConv(CONV_FUNC(_conv), None)
    handle = ctypes.c_void_p()
    out = {"start": None, "open": None, "close": None, "open_ms": None, "close_ms": None, "pid": os.getpid()}
    out["start"] = pam.pam_start_confdir(a.service.encode(), a.user.encode("utf-8", "surrogateescape"),
                                         ctypes.byref(conv), a.confdir.encode(), ctypes.byref(handle))
    if out["start"] != 0:
        print(json.dumps(out))
        return 1
    for item, val in ((PAM_TTY, a.tty), (PAM_RHOST, a.rhost), (PAM_RUSER, a.ruser)):
        if val:
            pam.pam_set_item(handle, item, val.encode("utf-8", "surrogateescape"))
    t0 = time.monotonic()
    out["open"] = pam.pam_open_session(handle, 0)
    out["open_ms"] = int((time.monotonic() - t0) * 1000)
    if not a.no_close:
        t0 = time.monotonic()
        out["close"] = pam.pam_close_session(handle, 0)
        out["close_ms"] = int((time.monotonic() - t0) * 1000)
    pam.pam_end(handle, 0)
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
