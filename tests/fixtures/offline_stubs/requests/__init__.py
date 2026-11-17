"""Offline stand-in for `requests`, used only by tests/test_legacy_writers.py.

It never performs network I/O. Every attempt is recorded in the file named by
WRITER_TEST_NETWORK_LOG so tests can prove a command refused to run before any lookup.
"""

import os


def _blocked(*args, **kwargs):
    log = os.environ.get("WRITER_TEST_NETWORK_LOG")
    if log:
        with open(log, "a", encoding="utf-8") as stream:
            stream.write("attempt\n")
    raise RuntimeError("network disabled in tests")


class Session:
    def get(self, *args, **kwargs):
        _blocked()

    def close(self):
        pass


def get(*args, **kwargs):
    _blocked()
