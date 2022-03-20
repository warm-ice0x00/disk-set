import hashlib
import typing

import sympy


class DiskSet:
    def __init__(self, file: typing.BinaryIO, n: int, key_len: int) -> None:
        self.n = n
        self.m = sympy.nextprime(n << 1)
        self.key_len = key_len
        try:
            file.truncate(self.m * self.key_len)
        except OSError:
            pass
        self.file = file

    def __enter__(self) -> "DiskSet":
        return self

    def _hash(self, key: bytes) -> int:
        return int.from_bytes(hashlib.md5(key).digest(), "big") % self.m

    def put(self, key: bytes) -> None:
        h = self._hash(key)
        while True:
            self.file.seek(h * self.key_len)
            if not any(self.file.read(self.key_len)):
                self.file.seek(-self.key_len, 1)
                self.file.write(key)
                break
            h = (h + 1) % self.m

    def get(self, key: bytes) -> bool:
        h = self._hash(key)
        while True:
            self.file.seek(h * self.key_len)
            b = self.file.read(self.key_len)
            if not any(b):
                return False
            elif b == key:
                return True
            h = (h + 1) % self.m

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.file.close()


if __name__ == "__main__":
    with open(
        "pwned-passwords-ntlm-ordered-by-hash-v8.txt", "r", encoding="ascii"
    ) as f_in:
        N = sum(1 for _ in f_in)
        print("N = %d" % N)
    with open(
        "pwned-passwords-ntlm-ordered-by-hash-v8.txt", "r", encoding="ascii"
    ) as f_in, open("hash_set", "w+b") as f_out:
        with DiskSet(f_out, N, 16) as hash_set:
            for line in f_in:
                hash_set.put(bytes.fromhex(line[:32]))
