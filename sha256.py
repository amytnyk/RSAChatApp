class SHA:
    @staticmethod
    def _right_rotate(data: int, cnt: int) -> int:
        return (data >> cnt) | ((data & ((1 << cnt) - 1)) << (32 - cnt))

    @staticmethod
    def _right_shift(data: int, cnt: int) -> int:
        return data >> cnt

    @staticmethod
    def _bin_add(num1: int, num2: int) -> int:
        return (num1 + num2) & ((1 << 32) - 1)

    @staticmethod
    def checksum(data: bytes) -> bytes:
        size = len(data) + 1
        data += (128).to_bytes(1, 'big') + bytes((64 - size - 8) % 64) + ((size - 1) * 8).to_bytes(8, "big")

        h_arr = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

        k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

        for chunk_idx in range(0, len(data), 64):
            chunk = data[chunk_idx:chunk_idx + 64]
            w = [int.from_bytes(chunk[i * 4:i * 4 + 4], "big") for i in range(16)]
            for i in range(16, 64):
                s0 = SHA._right_rotate(w[i - 15], 7) ^ \
                     SHA._right_rotate(w[i - 15], 18) ^ \
                     SHA._right_shift(w[i - 15], 3)

                s1 = SHA._right_rotate(w[i - 2], 17) ^ \
                    SHA._right_rotate(w[i - 2], 19) ^ \
                    SHA._right_shift(w[i - 2], 10)

                w.append(SHA._bin_add(SHA._bin_add(w[i - 16], s0), SHA._bin_add(w[i - 7], s1)))

            a, b, c, d, e, f, g, h = h_arr[:8]
            for i in range(64):
                s0 = SHA._right_rotate(a, 2) ^ SHA._right_rotate(a, 13) ^ SHA._right_rotate(a, 22)
                s1 = SHA._right_rotate(e, 6) ^ SHA._right_rotate(e, 11) ^ SHA._right_rotate(e, 25)
                choice = (e & f) ^ (~e & ((1 << 32) - 1) & g)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp1 = SHA._bin_add(SHA._bin_add(SHA._bin_add(h, s1), SHA._bin_add(choice, k[i])), w[i])
                temp2 = SHA._bin_add(s0, maj)
                h = g
                g = f
                f = e
                e = SHA._bin_add(d, temp1)
                d = c
                c = b
                b = a
                a = SHA._bin_add(temp1, temp2)

            for i in range(8):
                h_arr[i] = SHA._bin_add(h_arr[i], [a, b, c, d, e, f, g, h][i])

        return b''.join(p.to_bytes(4, "big") for p in h_arr)
