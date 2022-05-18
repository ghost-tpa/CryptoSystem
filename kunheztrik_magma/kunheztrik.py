# python 3.9.5

# S-Box
S = [0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16,
     0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x04, 0x4d,
     0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba,
     0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1,
     0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21,
     0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
     0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8f, 0xa0,
     0x06, 0x0b, 0xed, 0x98, 0x7f, 0xd4, 0xd3, 0x1f,
     0xeb, 0x34, 0x2c, 0x51, 0xea, 0xc8, 0x48, 0xab,
     0xf2, 0x2a, 0x68, 0xa2, 0xfd, 0x3a, 0xce, 0xcc,
     0xb5, 0x70, 0x0e, 0x56, 0x08, 0x0c, 0x76, 0x12,
     0xbf, 0x72, 0x13, 0x47, 0x9c, 0xb7, 0x5d, 0x87,
     0x15, 0xa1, 0x96, 0x29, 0x10, 0x7b, 0x9a, 0xc7,
     0xf3, 0x91, 0x78, 0x6f, 0x9d, 0x9e, 0xb2, 0xb1,
     0x32, 0x75, 0x19, 0x3d, 0xff, 0x35, 0x8a, 0x7e,
     0x6d, 0x54, 0xc6, 0x80, 0xc3, 0xbd, 0x0d, 0x57,
     0xdf, 0xf5, 0x24, 0xa9, 0x3e, 0xa8, 0x43, 0xc9,
     0xd7, 0x79, 0xd6, 0xf6, 0x7c, 0x22, 0xb9, 0x03,
     0xe0, 0x0f, 0xec, 0xde, 0x7a, 0x94, 0xb0, 0xbc,
     0xdc, 0xe8, 0x28, 0x50, 0x4e, 0x33, 0x0a, 0x4a,
     0xa7, 0x97, 0x60, 0x73, 0x1e, 0x00, 0x62, 0x44,
     0x1a, 0xb8, 0x38, 0x82, 0x64, 0x9f, 0x26, 0x41,
     0xad, 0x45, 0x46, 0x92, 0x27, 0x5e, 0x55, 0x2f,
     0x8c, 0xa3, 0xa5, 0x7d, 0x69, 0xd5, 0x95, 0x3b,
     0x07, 0x58, 0xb3, 0x40, 0x86, 0xac, 0x1d, 0xf7,
     0x30, 0x37, 0x6b, 0xe4, 0x88, 0xd9, 0xe7, 0x89,
     0xe1, 0x1b, 0x83, 0x49, 0x4c, 0x3f, 0xf8, 0xfe,
     0x8d, 0x53, 0xaa, 0x90, 0xca, 0xd8, 0x85, 0x61,
     0x20, 0x71, 0x67, 0xa4, 0x2d, 0x2b, 0x09, 0x5b,
     0xcb, 0x9b, 0x25, 0xd0, 0xbe, 0xe5, 0x6c, 0x52,
     0x59, 0xa6, 0x74, 0xd2, 0xe6, 0xf4, 0xb4, 0xc0,
     0xd1, 0x66, 0xaf, 0xc2, 0x39, 0x4b, 0x63, 0xb6]

# reverse of S-Box
S2 = [0xa5, 0x2d, 0x32, 0x8f, 0x0e, 0x30, 0x38, 0xc0,
      0x54, 0xe6, 0x9e, 0x39, 0x55, 0x7e, 0x52, 0x91,
      0x64, 0x03, 0x57, 0x5a, 0x1c, 0x60, 0x07, 0x18,
      0x21, 0x72, 0xa8, 0xd1, 0x29, 0xc6, 0xa4, 0x3f,
      0xe0, 0x27, 0x8d, 0x0c, 0x82, 0xea, 0xae, 0xb4,
      0x9a, 0x63, 0x49, 0xe5, 0x42, 0xe4, 0x15, 0xb7,
      0xc8, 0x06, 0x70, 0x9d, 0x41, 0x75, 0x19, 0xc9,
      0xaa, 0xfc, 0x4d, 0xbf, 0x2a, 0x73, 0x84, 0xd5,
      0xc3, 0xaf, 0x2b, 0x86, 0xa7, 0xb1, 0xb2, 0x5b,
      0x46, 0xd3, 0x9f, 0xfd, 0xd4, 0x0f, 0x9c, 0x2f,
      0x9b, 0x43, 0xef, 0xd9, 0x79, 0xb6, 0x53, 0x7f,
      0xc1, 0xf0, 0x23, 0xe7, 0x25, 0x5e, 0xb5, 0x1e,
      0xa2, 0xdf, 0xa6, 0xfe, 0xac, 0x22, 0xf9, 0xe2,
      0x4a, 0xbc, 0x35, 0xca, 0xee, 0x78, 0x05, 0x6b,
      0x51, 0xe1, 0x59, 0xa3, 0xf2, 0x71, 0x56, 0x11,
      0x6a, 0x89, 0x94, 0x65, 0x8c, 0xbb, 0x77, 0x3c,
      0x7b, 0x28, 0xab, 0xd2, 0x31, 0xde, 0xc4, 0x5f,
      0xcc, 0xcf, 0x76, 0x2c, 0xb8, 0xd8, 0x2e, 0x36,
      0xdb, 0x69, 0xb3, 0x14, 0x95, 0xbe, 0x62, 0xa1,
      0x3b, 0x16, 0x66, 0xe9, 0x5c, 0x6c, 0x6d, 0xad,
      0x37, 0x61, 0x4b, 0xb9, 0xe3, 0xba, 0xf1, 0xa0,
      0x85, 0x83, 0xda, 0x47, 0xc5, 0xb0, 0x33, 0xfa,
      0x96, 0x6f, 0x6e, 0xc2, 0xf6, 0x50, 0xff, 0x5d,
      0xa9, 0x8e, 0x17, 0x1b, 0x97, 0x7d, 0xec, 0x58,
      0xf7, 0x1f, 0xfb, 0x7c, 0x09, 0x0d, 0x7a, 0x67,
      0x45, 0x87, 0xdc, 0xe8, 0x4f, 0x1d, 0x4e, 0x04,
      0xeb, 0xf8, 0xf3, 0x3e, 0x3d, 0xbd, 0x8a, 0x88,
      0xdd, 0xcd, 0x0b, 0x13, 0x98, 0x02, 0x93, 0x80,
      0x90, 0xd0, 0x24, 0x34, 0xcb, 0xed, 0xf4, 0xce,
      0x99, 0x10, 0x44, 0x40, 0x92, 0x3a, 0x01, 0x26,
      0x12, 0x1a, 0x48, 0x68, 0xf5, 0x81, 0x8b, 0xc7,
      0xd6, 0x20, 0x0a, 0x08, 0x00, 0x4c, 0xd7, 0x74]

# round const
C = [0x6ea276726c487ab85d27bd10dd849401, 0xdc87ece4d890f4b3ba4eb92079cbeb02,
     0xb2259a96b4d88e0be7690430a44f7f03, 0x7bcd1b0b73e32ba5b79cb140f2551504,
     0x156f6d791fab511deabb0c502fd18105, 0xa74af7efab73df160dd208608b9efe06,
     0xc9e8819dc73ba5ae50f5b570561a6a07, 0xf6593616e6055689adfba18027aa2a08,
     0x98fb40648a4d2c31f0dc1c90fa2ebe09, 0x2adedaf23e95a23a17b518a05e61c10a,
     0x447cac8052ddd8824a92a5b083e5550b, 0x8d942d1d95e67d2c1a6710c0d5ff3f0c,
     0xe3365b6ff9ae07944740add0087bab0d, 0x5113c1f94d76899fa029a9e0ac34d40e,
     0x3fb1b78b213ef327fd0e14f071b0400f, 0x2fb26c2c0f0aacd1993581c34e975410,
     0x41101a5e6342d669c4123cd39313c011, 0xf33580c8d79a5862237b38e3375cbf12,
     0x9d97f6babbd222da7e5c85f3ead82b13, 0x547f77277ce987742ea93083bcc24114,
     0x3add015510a1fdcc738e8d936146d515, 0x88f89bc3a47973c794e789a3c509aa16,
     0xe65aedb1c831097fc9c034b3188d3e17, 0xd9eb5a3ae90ffa5834ce2043693d7e18,
     0xb7492c48854780e069e99d53b4b9ea19, 0x56cb6de319f0eeb8e80996310f6951a,
     0x6bcec0ac5dd77453d3a72473cd72011b, 0xa22641319aecd1fd835291039b686b1c,
     0xcc843743f6a4ab45de752c1346ecff1d, 0x7ea1add5427c254e391c2823e2a3801e,
     0x1003dba72e345ff6643b95333f27141f, 0x5ea7d8581e149b61f16ac1459ceda820]


def main() -> None:
    k = 0x8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
    a = 0x1122334455667700ffeeddccbbaa9988
    aRKey = fRoundKey(k)
    print("CipherText: ", hex(fEncrypt(aRKey, a)))
    print("PlainText: ", hex(fDecrypt(aRKey, fEncrypt(aRKey, a))))
    print("Check: ", fDecrypt(aRKey, fEncrypt(aRKey, a)) == a)


def fEncrypt(k: list, a: int) -> int:
    """
    :param k: 128-bit vector
    :param a: 128-bit vector
    :return: 128-bit vector
    """
    for i in range(9):
        data = fRouFuncEncr(k[i], a)
        a = data
    return fKeyadd(k[len(k) - 1], a)


def fDecrypt(k: list, a: int) -> int:
    """
    :param k: 128-bit vector
    :param a: 128-bit vector
    :return: 128-bit vector
    """
    for i in range(9):
        data = fRoundFuncDeCr(k[len(k) - 1 - i], a)
        a = data
    return fKeyadd(k[0], a)


def fRouFuncEncr(k: int, a: int):
    """
    :param k: 128-bit vector
    :param a: 128-bit vector
    :return: 128-bit vector
    """
    return fLiner(fNonLiner(S, fKeyadd(k, a)))


def fRoundFuncDeCr(k: int, a: int):
    """
    :param k: 128-bit vector
    :param a: 128-bit vector
    :return: 128-bit vector
    """
    return fNonLiner(S2, fRevL(fKeyadd(k, a)))


def fF(k: int, a: int) -> int:
    """
    :param k: 128-bit vector
    :param a: 128-bit vector
    :return: 128-bit vector
    """
    # L = a >> 128
    # R = a & 0xffffffffffffffffffffffffffffffff
    # ((fLiner(fNonLiner(S, fKeyadd(k, L))) ^ R) << 128) ^ L
    return ((fLiner(fNonLiner(S, fKeyadd(k, a >> 128))) ^ (a & 0xffffffffffffffffffffffffffffffff)) << 128) ^ (a >> 128)


def fRoundKey(k: int) -> list:
    """
    :param k: 256-bit vector
    :return: list 10 * 128-bit round key
    """
    aTemp = []
    aRes = [k >> 128, k & 0xffffffffffffffffffffffffffffffff]  # init
    for j in range(4):
        for i in range(8):
            data = fF(C[j * 8 + i], k)
            aTemp.append(data)
            k = data
        aRes.append(k >> 128)
        aRes.append(k & 0xffffffffffffffffffffffffffffffff)

    return aRes


def fR(a: int) -> int:
    """
    :param a: 128-bit vector
    :return: 128-bit vector
    """
    # data1 = fl(a) << 120
    # data2 = (a >> 8) & 0xffffffffffffffffffffffffffffff
    # data1 ^ data2
    return (fl(a) << 120) ^ ((a >> 8) & 0xffffffffffffffffffffffffffffff)


def fRevR(a: int) -> int:  # Rev = Reverse
    """

    :param a: 128-bit vector
    :return: 128-bit vector
    """
    # data1 = (a & 0x00ffffffffffffffffffffffffffffff) << 8
    # data2 = fl(((a & 0x00ffffffffffffffffffffffffffffff) << 8) ^ (a >> 120))
    # data1 ^ data2
    return ((a & 0xffffffffffffffffffffffffffffff) << 8) ^ \
           fl(((a & 0xffffffffffffffffffffffffffffff) << 8) ^ (a >> 120))


def fRevL(a: int) -> int:
    """
    :param a: 128-bit vector
    :return: 128-bit vector
    """
    for i in range(16):
        data = fRevR(a)
        a = data
    return a


def fLiner(a: int) -> int:
    """
    :param a: 128-bit vector
    :return: 128-bit vector
    """
    for i in range(16):
        data = fR(a)
        a = data
    return a


def fKeyadd(k: int, a: int) -> int:
    """
    :param k: 128-bit vector
    :param a: 128-bit vector
    :return: 128-bit vector
    """
    return k ^ a


def fl(a: int) -> int:  # a - V128
    """
    :param a: 128-bit vector
    :return: 128-bit vector
    """
    return fMul(a >> 120, 0x94) ^ fMul((a >> 112) & 0xff, 0x20) ^ \
           fMul((a >> 104) & 0xff, 0x85) ^ fMul((a >> 96) & 0xff, 0x10) ^ \
           fMul((a >> 88) & 0xff, 0xc2) ^ fMul((a >> 80) & 0xff, 0xc0) ^ \
           fMul((a >> 72) & 0xff, 0x01) ^ fMul((a >> 64) & 0xff, 0xfb) ^ \
           fMul((a >> 56) & 0xff, 0x01) ^ fMul((a >> 48) & 0xff, 0xc0) ^ \
           fMul((a >> 40) & 0xff, 0xc2) ^ fMul((a >> 32) & 0xff, 0x10) ^ \
           fMul((a >> 24) & 0xff, 0x85) ^ fMul((a >> 16) & 0xff, 0x20) ^ \
           fMul((a >> 8) & 0xff, 0x94) ^ fMul((a >> 0) & 0xff, 0x01)


def fNonLiner(Sbox: list, a: int) -> int:
    """
    :param Sbox: type of S-Box (original or reverse)
    :param a: 128-bit vector
    :return: 128-bit vector
    """
    return ((Sbox[a >> 120]) << 120) ^ ((Sbox[(a >> 112) & 0xff]) << 112) ^ \
           ((Sbox[(a >> 104) & 0xff]) << 104) ^ ((Sbox[(a >> 96) & 0xff]) << 96) ^ \
           ((Sbox[(a >> 88) & 0xff]) << 88) ^ ((Sbox[(a >> 80) & 0xff]) << 80) ^ \
           ((Sbox[(a >> 72) & 0xff]) << 72) ^ ((Sbox[(a >> 64) & 0xff]) << 64) ^ \
           ((Sbox[(a >> 56) & 0xff]) << 56) ^ ((Sbox[(a >> 48) & 0xff]) << 48) ^ \
           ((Sbox[(a >> 40) & 0xff]) << 40) ^ ((Sbox[(a >> 32) & 0xff]) << 32) ^ \
           ((Sbox[(a >> 24) & 0xff]) << 24) ^ ((Sbox[(a >> 16) & 0xff]) << 16) ^ \
           ((Sbox[(a >> 8) & 0xff]) << 8) ^ (Sbox[a & 0xff])


def fMul(p1: int, p2: int) -> int:
    """
        Умножение многочлены p1 и p2 над конечным полем GF(2^8) -- gx = 111000011
    """
    step: int = 0
    res: int = 0b0
    gx: int = 0b111000011  # x^8 + x^7 + x^6 + x + 1
    while p2 != 0:
        if p2 & 0b1 == 1:
            res ^= (p1 << step)
        while res > pow(2, 8) - 1:  # деление с остаком на многочлен gX
            res ^= gx << (res.bit_length() - gx.bit_length())
        p2 >>= 1
        step += 1

    return res


if __name__ == '__main__':
    main()
