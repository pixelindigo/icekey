from .utils import gf_mult, gf_exp7
import struct

# Modulo values for the S-boxes
ICE_SMOD = [[333, 313, 505, 369],
            [379, 375, 319, 391],
            [361, 445, 451, 397],
            [397, 425, 395, 505]]

# XOR values for the S-boxes
ICE_SXOR = [[0x83, 0x85, 0x9b, 0xcd],
            [0xcc, 0xa7, 0xad, 0x41],
            [0x4b, 0x2e, 0xd4, 0x33],
            [0xea, 0xcb, 0x2e, 0x04]]

# Expanded permutation values for the P-box
ICE_PBOX = [0x00000001, 0x00000080, 0x00000400, 0x00002000,
            0x00080000, 0x00200000, 0x01000000, 0x40000000,
            0x00000008, 0x00000020, 0x00000100, 0x00004000,
            0x00010000, 0x00800000, 0x04000000, 0x20000000,
            0x00000004, 0x00000010, 0x00000200, 0x00008000,
            0x00020000, 0x00400000, 0x08000000, 0x10000000,
            0x00000002, 0x00000040, 0x00000800, 0x00001000,
            0x00040000, 0x00100000, 0x02000000, 0x80000000]


# The key rotation schedule
ICE_KEYROT = [0, 1, 2, 3, 2, 1, 3, 0,
              1, 3, 2, 0, 3, 1, 0, 2]


def ice_perm32(x):
    """Carry out the ICE 32-bit P-box permutation."""
    res = 0
    for p in ICE_PBOX:
        if x == 0:
            break
        if x & 1:
            res |= p
        x >>= 1

    return res


# The S-boxes
ICE_SBOX = [[], [], [], []]
for i in range(1024):
    col = (i >> 1) & 0xff
    row = (i & 0x1) | ((i & 0x200) >> 8)
    x = gf_exp7(col ^ ICE_SXOR[0][row], ICE_SMOD[0][row]) << 24
    ICE_SBOX[0].append(ice_perm32(x))

    x = gf_exp7(col ^ ICE_SXOR[1][row], ICE_SMOD[1][row]) << 16
    ICE_SBOX[1].append(ice_perm32(x))

    x = gf_exp7(col ^ ICE_SXOR[2][row], ICE_SMOD[2][row]) << 8
    ICE_SBOX[2].append(ice_perm32(x))

    x = gf_exp7(col ^ ICE_SXOR[3][row], ICE_SMOD[3][row])
    ICE_SBOX[3].append(ice_perm32(x))


class IceKey:

    def __init__(self, n, key):
        if n < 1:
            self.size = 1
            self.rounds = 8
        else:
            self.size = n
            self.rounds = n * 16
        if len(key) / 8 != self.size:
            raise ValueError('key length must be {} bytes'
                             .format(self.size * 8))

        self.keysched = [[]] * self.rounds

        if self.rounds == 8:
            kb = [(key[(3 - i)*2] << 8) | key[(3 - i)*2 + 1] for i in range(4)]
            self._schedule_build(kb, 0, ICE_KEYROT[:8])
            return

        for i in range(self.size):
            kb = [(key[i*8 + (3 - j)*2] << 8) | key[i*8 + (3 - j)*2 + 1]
                  for j in range(4)]
            kb = self._schedule_build(kb, i*8, ICE_KEYROT[:8])
            self._schedule_build(kb, self.rounds - 8 - i*8, ICE_KEYROT[8:])

    def _ice_f(self, p, sk):
        """The single round ICE f function."""
        # Left half expansion
        tl = ((p >> 16) & 0x3ff) | (((p >> 14) | (p << 18)) & 0xffc00)

        # Right half expansion
        tr = (p & 0x3ff) | ((p << 2) & 0xffc00)

        # Perform the salt permutation
        # al = (tr & sk[2]) | (tl & ~sk[2])
        # ar = (tl & sk[2]) | (tr & ~sk[2])
        al = sk[2] & (tl ^ tr)
        ar = al ^ tr
        al ^= tl

        # XOR with the subkey
        al ^= sk[0]
        ar ^= sk[1]

        # S-box lookup and permutation
        return (ICE_SBOX[0][al >> 10] | ICE_SBOX[1][al & 0x3ff]
                | ICE_SBOX[2][ar >> 10] | ICE_SBOX[3][ar & 0x3ff])

    def encrypt_block(self, ptext):
        """Encrypt a block of 8 bytes of data with the given ICE key."""
        left, right = struct.unpack('>II', ptext)

        for i in range(0, self.rounds, 2):
            left ^= self._ice_f(right, self.keysched[i])
            right ^= self._ice_f(left, self.keysched[i + 1])

        return struct.pack('>II', right, left)

    def decrypt_block(self, ctext):
        """Decrypt a block of 8 bytes of data with the given ICE key."""
        left, right = struct.unpack('>II', ctext)

        for i in range(self.rounds - 1, 0, -2):
            left ^= self._ice_f(right, self.keysched[i])
            right ^= self._ice_f(left, self.keysched[i - 1])

        return struct.pack('>II', right, left)

    def encrypt(self, ptext):
        if len(ptext) % 8 != 0:
            raise ValueError("plaintext size must be a multiple of 8 bytes")
        return b''.join([self.encrypt_block(ptext[i:i+8])
                         for i in range(0, len(ptext), 8)])

    def decrypt(self, ctext):
        if len(ctext) % 8 != 0:
            raise ValueError("ciphertext size must be a multiple of 8 bytes")
        return b''.join([self.decrypt_block(ctext[i:i+8])
                         for i in range(0, len(ctext), 8)])

    def _schedule_build(self, kb, n, keyrot):
        """Set 8 rounds [n, n+7] of the key schedule of an ICE key."""
        for i in range(8):
            kr = keyrot[i]
            self.keysched[n + i] = [0, 0, 0]

            for j in range(15):
                for k in range(4):
                    curr_kb = kb[(kr + k) & 3]
                    curr_sk = self.keysched[n + i][j % 3]
                    bit = curr_kb & 1

                    self.keysched[n + i][j % 3] = (curr_sk << 1) | bit
                    kb[(kr + k) & 3] = (curr_kb >> 1) | ((bit ^ 1) << 15)
        return kb
