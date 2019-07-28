def gf_mult(a, b, m):
    """Galois Field multiplication of a by b, modulo m.

    Just like arithmetic multiplication, except that additions and
    subtractions are replaced by XOR.
    """
    res = 0
    while b != 0:
        if b & 1:
            res ^= a
        a <<= 1
        b >>= 1

        if a >= 256:
            a ^= m
    return res


def gf_exp7(b, m):
    """Galois Field exponentiation.

    Raise the base to the power of 7, modulo m.
    """
    if b == 0:
        return 0

    x = gf_mult(b, b, m)
    x = gf_mult(b, x, m)
    x = gf_mult(x, x, m)
    return gf_mult(b, x, m)
