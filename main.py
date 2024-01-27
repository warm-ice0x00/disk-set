import hashlib
import json
import os
import string
import sys

import typing

sys.path.append(os.getcwd())
import disk_set


def truncated_sha1(pwd):  # type: (typing.Text) -> bytes
    return hashlib.sha1(pwd.encode("utf8")).digest()[:8]


def brute_force(length, strings):
    # type: (int, typing.Sequence[typing.Text]) -> typing.Iterator[typing.Text]
    stack = [
        [s] for s in reversed(strings)
    ]  # type: typing.List[typing.List[typing.Text]]
    while stack:
        cur = stack.pop()  # type: typing.List[typing.Text]
        yield "".join(cur)
        if len(cur) < length:
            stack.extend(cur + [s] for s in reversed(strings))


with open("hash_set_truncated_size_847223402", "rb") as f:
    N = 847223402  # type: int
    with disk_set.DiskSet(f, N, 8) as ds:
        t = tuple(
            p
            for p in brute_force(3, string.ascii_lowercase)
            if truncated_sha1(p) not in ds
        )  # type: typing.Tuple[typing.Text, ...]
        print(json.dumps(t, separators=(",", ":")))
