# python 3.9.5

H = [[0x1, 0x3, 0x4, 0x5, 0x6, 0x8, 0xb, 0x7],
     [0x3, 0x1, 0x5, 0x4, 0x8, 0x6, 0x7, 0xb],
     [0x4, 0x5, 0x1, 0x3, 0xb, 0x7, 0x6, 0x8],
     [0x5, 0x4, 0x3, 0x1, 0x7, 0xb, 0x8, 0x6],
     [0x6, 0x8, 0xb, 0x7, 0x1, 0x3, 0x4, 0x5],
     [0x8, 0x6, 0x7, 0xb, 0x3, 0x1, 0x5, 0x4],
     [0xb, 0x7, 0x6, 0x8, 0x4, 0x5, 0x1, 0x3],
     [0x7, 0xb, 0x8, 0x6, 0x5, 0x4, 0x3, 0x1]]

S = [0xa7, 0xd3, 0xe6, 0x71, 0xd0, 0xac, 0x4d, 0x79,
     0x3a, 0xc9, 0x91, 0xfc, 0x1e, 0x47, 0x54, 0xbd,
     0x8c, 0xa5, 0x7a, 0xfb, 0x63, 0xb8, 0xdd, 0xd4,
     0xe5, 0xb3, 0xc5, 0xbe, 0xa9, 0x88, 0xc, 0xa2,
     0x39, 0xdf, 0x29, 0xda, 0x2b, 0xa8, 0xcb, 0x4c,
     0x4b, 0x22, 0xaa, 0x24, 0x41, 0x70, 0xa6, 0xf9,
     0x5a, 0xe2, 0xb0, 0x36, 0x7d, 0xe4, 0x33, 0xff,
     0x60, 0x20, 0x8, 0x8b, 0x5e, 0xab, 0x7f, 0x78,
     0x7c, 0x2c, 0x57, 0xd2, 0xdc, 0x6d, 0x7e, 0xd,
     0x53, 0x94, 0xc3, 0x28, 0x27, 0x6, 0x5f, 0xad,
     0x67, 0x5c, 0x55, 0x48, 0xe, 0x52, 0xea, 0x42,
     0x5b, 0x5d, 0x30, 0x58, 0x51, 0x59, 0x3c, 0x4e,
     0x38, 0x8a, 0x72, 0x14, 0xe7, 0xc6, 0xde, 0x50,
     0x8e, 0x92, 0xd1, 0x77, 0x93, 0x45, 0x9a, 0xce,
     0x2d, 0x3, 0x62, 0xb6, 0xb9, 0xbf, 0x96, 0x6b,
     0x3f, 0x7, 0x12, 0xae, 0x40, 0x34, 0x46, 0x3e,
     0xdb, 0xcf, 0xec, 0xcc, 0xc1, 0xa1, 0xc0, 0xd6,
     0x1d, 0xf4, 0x61, 0x3b, 0x10, 0xd8, 0x68, 0xa0,
     0xb1, 0xa, 0x69, 0x6c, 0x49, 0xfa, 0x76, 0xc4,
     0x9e, 0x9b, 0x6e, 0x99, 0xc2, 0xb7, 0x98, 0xbc,
     0x8f, 0x85, 0x1f, 0xb4, 0xf8, 0x11, 0x2e, 0x0,
     0x25, 0x1c, 0x2a, 0x3d, 0x5, 0x4f, 0x7b, 0xb2,
     0x32, 0x90, 0xaf, 0x19, 0xa3, 0xf7, 0x73, 0x9d,
     0x15, 0x74, 0xee, 0xca, 0x9f, 0xf, 0x1b, 0x75,
     0x86, 0x84, 0x9c, 0x4a, 0x97, 0x1a, 0x65, 0xf6,
     0xed, 0x9, 0xbb, 0x26, 0x83, 0xeb, 0x6f, 0x81,
     0x4, 0x6a, 0x43, 0x1, 0x17, 0xe1, 0x87, 0xf5,
     0x8d, 0xe3, 0x23, 0x80, 0x44, 0x16, 0x66, 0x21,
     0xfe, 0xd5, 0x31, 0xd9, 0x35, 0x18, 0x2, 0x64,
     0xf2, 0xf1, 0x56, 0xcd, 0x82, 0xc8, 0xba, 0xf0,
     0xef, 0xe9, 0xe8, 0xfd, 0x89, 0xd7, 0xc7, 0xb5,
     0xa4, 0x2f, 0x95, 0x13, 0xb, 0xf3, 0xe0, 0x37]

C = [0xa7d3e671d0ac4d79, 0x3ac991fc1e4754bd, 0x8ca57afb63b8ddd4,
     0xe5b3c5bea9880ca2, 0x39df29da2ba8cb4c, 0x4b22aa244170a6f9,
     0x5ae2b0367de433ff, 0x6020088b5eab7f78, 0x7c2c57d2dc6d7e0d]


def main():
    keyT = 0x40000000000000000000000000000000
    test = 0x0000000000000000
    key = KeySche(keyT)

    print("Cipher text: {}".format(hex(encrypt(key, test))))
    print("Plain text: {}".format(hex(decrypt(key, encrypt(key, test)))))
    print("Check: {}".format(test == decrypt(key, encrypt(key, test))))


def NonLi(a: int) -> int:  # a -  V64
    """
        Non liner layer
    :param a: 64-bit vector
    :return: 64-bit vector
    """
    return (S[a >> 56] << 56) ^ (S[(a >> 48) & 0xff] << 48) ^ \
           (S[(a >> 40) & 0xff] << 40) ^ (S[(a >> 32) & 0xff] << 32) ^ \
           (S[(a >> 24) & 0xff] << 24) ^ (S[(a >> 16) & 0xff] << 16) ^ \
           (S[(a >> 8) & 0xff] << 8) ^ S[a & 0xff]


def Diffu(a: int) -> int:  # a - V64
    """
        Liner layer
    :param a: 64-bit vector
    :return: 64-bit vector
    """
    return (d(a, H[0]) << 56) ^ (d(a, H[1]) << 48) ^ \
           (d(a, H[2]) << 40) ^ (d(a, H[3]) << 32) ^ \
           (d(a, H[4]) << 24) ^ (d(a, H[5]) << 16) ^ \
           (d(a, H[6]) << 8) ^ d(a, H[7])


def KeyAdd(k: int, a: int) -> int:
    """
    :param k: 64-bit vector
    :param a: 64-bit vector
    :return: 64-bit vector
    """
    return k ^ a


def RFunc(k: int, a: int) -> int:
    """
        Round function
    :param k: 64-bit vector
    :param a: 64-bit vector
    :return: 64-bit vector
    """
    return KeyAdd(k, Diffu(NonLi(a)))


def Feil(k: int, const: int) -> int:
    """
        Feistel network
    :param k: 128-bit vector
    :param const: 64-bit vector (round constant)
    :return: 128-bit vector
    """
    L = k >> 64
    R = k & 0xffffffffffffffff
    return (R << 64) ^ (L ^ RFunc(const, R))


def KeySche(k: int) -> list:
    """
    :param k: 128-bit vector
    :return: list 9 round key (128-bit vector)
    """
    aRes = []
    for i in range(9):
        data = Feil(k, C[i])
        aRes.append(data & 0xffffffffffffffff)
        k = data
    return aRes


def encrypt(RKey: list, a: int) -> int:
    st = KeyAdd(RKey[0], a)
    for i in range(1, 8):
        temp = RFunc(RKey[i], st)
        st = temp
    return KeyAdd(RKey[8], NonLi(st))


def decrypt(RKey: list, a: int) -> int:
    st = KeyAdd(RKey[8], a)
    for i in range(7, 0, -1):
        temp = RFunc(Diffu(RKey[i]), st)
        st = temp
    return KeyAdd(RKey[0], NonLi(st))


def d(a: int, b: list) -> int:
    """
        Dot product vector and list
    :param a: 64-bit vector
    :param b: Lines of matrix H
    :return:  64-bit vector
    """
    res = 0b0
    for i in range(len(H[0])):
        res ^= fMul((a >> (64 - (8 * (i + 1))) & 0xff), b[i])
    return res


def fMul(p1: int, p2: int) -> int:
    """
        Polynomial multiplication over finite fields GF(2^8), gx = 100011101
        Умножение многочлены p1 и p2 над конечным полем GF(2^8), gx = 100011101
    """
    step: int = 0
    res: int = 0b0
    gx: int = 0b100011101  # x^8 + x^4 + x^3 + x^2 + 1
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
