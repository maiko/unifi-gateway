# -*- coding: utf-8 -*-
import os
import tempfile


def atomic_write(path, write, *, mode=None):
    """Replace a file after flushing it, preserving permissions unless specified."""
    directory = os.path.dirname(os.path.abspath(path))
    if mode is None:
        try:
            mode = os.stat(path).st_mode & 0o7777
        except FileNotFoundError:
            mode = 0o600
    fd, tmp = tempfile.mkstemp(prefix='.' + os.path.basename(path) + '.', dir=directory)
    try:
        with os.fdopen(fd, 'w') as f:
            write(f)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
