import binascii
import codecs
import struct
import sys
import types

import typing

T = typing.TypeVar("T")


def is_prime(x):  # type: (int) -> bool
    o = 4  # type: int
    i = 5  # type: int
    while True:
        q = x // i  # type: int
        if q < i:
            return True
        if x == q * i:
            return False
        o ^= 6
        i += o


def next_prime(x):  # type: (int) -> int
    """https://stackoverflow.com/a/5694432"""
    if x < 3:
        return 2
    elif x == 3:
        return 3
    elif x < 6:
        return 5
    k = x // 6  # type: int
    i = x - 6 * k  # type: int
    o = 1 if i < 2 else 5  # type: int
    x = 6 * k + o
    i = (3 + o) // 2
    while not is_prime(x):
        i ^= 6
        x += i
    return x


class DiskSet:
    def __init__(self, f, capacity, key_len):
        # type: (typing.BinaryIO, int, int) -> None
        self.capacity = capacity  # type: int
        self.m = next_prime(self.capacity * 4 // 3)  # type: int
        self.n = 0  # type: int
        self.key_len = key_len  # type: int
        self.fmt = "=%dB" % self.key_len  # type: str
        self.file = f  # type: typing.BinaryIO
        try:
            self.file.seek(self.m * self.key_len - 1)
            self.file.write(b"\0")
        except IOError:
            pass

    def __enter__(self):  # type: () -> DiskSet
        return self

    def _hash(self, key):  # type: (bytes) -> int
        """https://www.cse.yorku.ca/~oz/hash.html"""
        h = 0  # type: int
        t = struct.unpack(self.fmt, key)  # type: typing.Tuple[int, ...]
        for b in t:
            h = b + (h << 6) + (h << 16) - h
        return h % self.m

    def put(self, key):  # type: (bytes) -> None
        h = self._hash(key)  # type: int
        key_tuple = struct.unpack(self.fmt, key)  # type: typing.Tuple[int, ...]
        while 1:
            self.file.seek(h * self.key_len)
            t = struct.unpack(
                self.fmt, self.file.read(self.key_len)
            )  # type: typing.Tuple[int, ...]
            if t == key_tuple:
                return
            elif not any(t):
                self.file.seek(-self.key_len, 1)
                self.file.write(key)
                break
            h = (h + 1) % self.m
        self.n += 1

    def __contains__(self, key):  # type: (bytes) -> bool
        h = self._hash(key)  # type: int
        key_tuple = struct.unpack(self.fmt, key)  # type: typing.Tuple[int, ...]
        while 1:
            self.file.seek(h * self.key_len)
            t = struct.unpack(
                self.fmt, self.file.read(self.key_len)
            )  # type: typing.Tuple[int, ...]
            if not any(t):
                return False
            elif t == key_tuple:
                return True
            h = (h + 1) % self.m

    __getitem__ = __contains__

    def __delitem__(self, key):  # type: (bytes) -> None
        h = self._hash(key)  # type: int
        key_tuple = struct.unpack(self.fmt, key)  # type: typing.Tuple[int, ...]
        while 1:
            self.file.seek(h * self.key_len)
            t = struct.unpack(
                self.fmt, self.file.read(self.key_len)
            )  # type: typing.Tuple[int, ...]
            if not any(t):
                return
            elif t == key_tuple:
                self.file.seek(-self.key_len, 1)
                self.file.write(b"\0" * self.key_len)
                break
            h = (h + 1) % self.m
        h = (h + 1) % self.m
        while 1:
            self.file.seek(h * self.key_len)
            key_redo = self.file.read(self.key_len)  # type: bytes
            t = struct.unpack(self.fmt, key_redo)
            if not any(t):
                break
            self.file.seek(-self.key_len, 1)
            self.file.write(b"\0" * self.key_len)
            h2 = self._hash(key_redo)  # type: int
            t_redo = struct.unpack(self.fmt, key_redo)  # type: typing.Tuple[int, ...]
            while 1:
                self.file.seek(h2 * self.key_len)
                t2 = struct.unpack(
                    self.fmt, self.file.read(self.key_len)
                )  # type: typing.Tuple[int, ...]
                if t2 == t_redo:
                    break
                elif not any(t2):
                    self.file.seek(-self.key_len, 1)
                    self.file.write(key_redo)
                    break
                h2 = (h2 + 1) % self.m
            h = (h + 1) % self.m
        self.n -= 1

    def __len__(self):  # type: () -> int
        return self.n

    def __exit__(
        self,
        exc_type,  # type: typing.Optional[typing.Type[BaseException]]
        exc_val,  # type: typing.Optional[BaseException]
        exc_tb,  # type: typing.Optional[types.TracebackType]
    ):  # type: (...) -> None
        self.file.close()


if __name__ == "__main__":

    def unique(iterable):  # type: (typing.Iterable[T]) -> typing.Iterator[T]
        it = iter(iterable)  # type: typing.Iterator[T]
        previous = next(it)  # type: T
        yield previous
        for i in it:
            if i != previous:
                yield i
            previous = i

    def progress(it, count, size=60):
        # type: (typing.Iterable[T], int, int) -> typing.Iterator[T]
        def show(j):  # type: (int) -> None
            x = size * j // count  # type: int
            sys.stdout.write("[%s%s] %i/%i\r" % ("#" * x, "." * (size - x), j, count))
            sys.stdout.flush()

        show(0)
        for i, item in enumerate(it):
            yield item
            show(i + 1)
        sys.stdout.write("\n")
        sys.stdout.flush()

    with codecs.open(
        "pwned-passwords-sha1-ordered-by-hash-v8.txt", encoding="ascii"
    ) as f_in:
        N = sum(1 for _ in unique(s[:16] for s in f_in))
        print("N = %d" % N)
        f_in.seek(0)
        with open("hash_set_truncated_size_%d" % N, "w+b") as f_out, DiskSet(
            f_out, N, 8
        ) as hash_set:
            for line in progress(unique(f_in), N):
                hash_set.put(binascii.a2b_hex(line[:16]))
