from dataclasses import dataclass
from functools import cache
from random import randrange
from typing import List, Tuple


class RSA:
    @dataclass
    class PublicKey:
        n: int
        e: int
        bits: int

        def encrypt(self, msg: bytes) -> bytes:
            msg = len(msg).to_bytes(4, "big") + msg
            chunked: List[int] = []
            size = self.bits // 4
            for i in range(0, len(msg), size):
                num = 0
                for j in range(0, min(size, len(msg) - i)):
                    num |= msg[i + j] << (8 * j)
                chunked.append(num)
            return b''.join(
                pow(m, self.e, self.n).to_bytes(size, "big") for m in chunked)

        def to_bytes(self) -> bytes:
            return self.bits.to_bytes(2, "big") + \
                   self.n.to_bytes(self.bits // 4, "big") + \
                   self.e.to_bytes(self.bits // 4, "big")

        @staticmethod
        def from_bytes(data: bytes):
            bits = int.from_bytes(data[:2], "big")
            n = int.from_bytes(data[2:2 + bits // 4], "big")
            e = int.from_bytes(data[2 + bits // 4:2 + bits // 2], "big")
            return RSA.PublicKey(n, e, bits)

    @dataclass
    class PrivateKey:
        n: int
        d: int
        bits: int

        def decrypt(self, encrypted: bytes) -> bytes:
            chunked: List[int] = []
            size = self.bits // 4
            for i in range(0, len(encrypted), size):
                chunked.append(int.from_bytes(encrypted[i:i + size], "big"))

            decrypted = b''.join(pow(m, self.d, self.n).to_bytes(size, "little") for m in chunked)
            msg_size = int.from_bytes(decrypted[:4], "big")
            return decrypted[4:msg_size + 4]

    def __init__(self, bits: int):
        self.bits = bits

    @staticmethod
    @cache
    def _get_small_primes() -> List[int]:
        return [i for i in range(2, 400)
                if all(i % j != 0 for j in range(2, i))]

    def _generate_low_prime(self) -> int:
        while True:
            p = randrange(2 ** (self.bits - 1) + 1, 2 ** self.bits - 1)
            if all(p % divisor != 0 for divisor in RSA._get_small_primes()):
                return p

    @staticmethod
    def _factor(p: int) -> Tuple[int, int]:
        r = 0
        d = p - 1
        while d % 2 == 0:
            d >>= 1
            r += 1
        return r, d

    @staticmethod
    def _is_prime(p: int) -> bool:  # Rabin-Muller test
        r, d = RSA._factor(p)

        for _ in range(10):
            x = pow(randrange(2, p - 2), d, p)
            if x != 1 and x != p - 1 and \
                    all(pow(x, 2 ** i, p) != p - 1 for i in range(r - 1)):
                return False
        return True

    def _generate_prime(self) -> int:
        while True:
            p = self._generate_low_prime()
            if RSA._is_prime(p):
                return p

    def generate_keys(self):
        p, q = self._generate_prime(), self._generate_prime()
        e = 65537
        d = pow(e, -1, (p - 1) * (q - 1))
        n = p * q
        return RSA.PublicKey(n, e, self.bits), RSA.PrivateKey(n, d, self.bits)
