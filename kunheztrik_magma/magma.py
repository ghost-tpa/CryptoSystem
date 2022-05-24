# python 3.9.5

S = ((0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1),
     (0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF),
     (0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0),
     (0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB),
     (0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC),
     (0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0),
     (0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7),
     (0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2))


def main() -> None:
    a: int = 0xfedcba9876543210
    k: int = 0xffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
    RouKey: int = fRKey(k)
    print("Encrypted Text: {}".format(hex(fEncrypt(RouKey, a))))
    print("Decrypted Text: {}".format(hex(fDecrypt(RouKey, fEncrypt(RouKey, a)))))
    print("Check: ", a == fDecrypt(RouKey, fEncrypt(RouKey, a)))


def fNonLiner(a: int) -> int:
    """
    :param a: 32-bit vector
    :return: 32-bit vector
    """
    return (S[7][a >> 28] << 28) ^ (S[6][(a >> 24) & 0xf] << 24) ^ \
           (S[5][(a >> 20) & 0xf] << 20) ^ (S[4][(a >> 16) & 0xf] << 16) ^ \
           (S[3][(a >> 12) & 0xf] << 12) ^ (S[2][(a >> 8) & 0xf] << 8) ^ \
           (S[1][(a >> 4) & 0xf] << 4) ^ (S[0][a & 0xf])


def fRKey(k: int) -> int:
    """
        algorithm key schedule
    :param k: 256-bit vector
    :return: 1024-bit vector (32 * 32-bit round key)
    """
    return (k << 768) ^ \
           ((k & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff) << 512) ^ \
           ((k & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff) << 256) ^ \
           ((k & 0xffffffff) << 224) ^ ((k >> 32 & 0xffffffff) << 192) ^ \
           ((k >> 64 & 0xffffffff) << 160) ^ ((k >> 96 & 0xffffffff) << 128) ^ \
           ((k >> 128 & 0xffffffff) << 96) ^ ((k >> 160 & 0xffffffff) << 64) ^ \
           ((k >> 192 & 0xffffffff) << 32) ^ (k >> 224 & 0xffffffff)


def fshift(a: int) -> int:
    """
        logical right shift 11 bit
    :param a: 32-bit vector
    :return: 32-bit vector
    """
    return ((a << 11) | (a >> 21)) & 0xffffffff  # 21 = 32-11


def fg(k: int, a: int) -> int:
    """
    :param k: 32-bit vector
    :param a: 32-bit vector
    :return: 32-bit vector
    """
    return fshift(fNonLiner((k + a) % pow(2, 32)))


def fG(k: int, a: int) -> int:
    """
    :param k: 32-bit vector
    :param a: 64-bit vector
    :return: 64-bit vector
    """
    # L = a >> 32
    # R = a & 0xffffffff
    return ((a & 0xffffffff) << 32) ^ ((a >> 32) ^ fg(k, a & 0xffffffff))


def fEncrypt(k: int, a: int) -> int:
    """
    :param k: 1024-bit vector  (32 * 32-bit round key)
    :param a: 32-bit vector
    :return: 32-bit vector
    """
    for i in range(32):
        rKey: int = (k >> (1024 - (32 * (i + 1)))) & 0xffffffff
        data: int = fG(rKey, a)
        a: int = data
    iRes: int = ((a & 0xffffffff) << 32) ^ (a >> 32)
    return iRes


def fDecrypt(k: int, a: int) -> int:
    """
    :param k: 1024-bit vector  (32 * 32-bit round key)
    :param a: 32-bit vector
    :return: 32-bit vector
    """
    for i in range(32):
        rKey: int = (k >> (32 * i)) & 0xffffffff
        data: int = fG(rKey, a)
        a: int = data
    iRes: int = ((a & 0xffffffff) << 32) ^ (a >> 32)
    return iRes


if __name__ == '__main__':
    main()
