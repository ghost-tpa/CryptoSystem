# python 3.9.5
# done 19.05.2022
"""
    Шифрсистем TOY-r:
    Число раундов = 31
    Длина длока = 64-бит
    Длина ключа = 80-бит

    Cryptosystem TOY-r
    Number of rounds - 32
    Block length - 64-bit
    Key length - 80-bit
"""
# S-box
S = (0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2)
# inverse of S-Box
S1 = (0x5, 0xe, 0xf, 0x8, 0xc, 0x1, 0x2, 0xd, 0xb, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xa)
# P-box
P = (0x00, 0x10, 0x20, 0x30, 0x01, 0x11, 0x21, 0x31,
     0x02, 0x12, 0x22, 0x32, 0x03, 0x13, 0x23, 0x33,
     0x04, 0x14, 0x24, 0x34, 0x05, 0x15, 0x25, 0x35,
     0x06, 0x16, 0x26, 0x36, 0x07, 0x17, 0x27, 0x37,
     0x08, 0x18, 0x28, 0x38, 0x09, 0x19, 0x29, 0x39,
     0x0a, 0x1a, 0x2a, 0x3a, 0x0b, 0x1b, 0x2b, 0x3b,
     0x0c, 0x1c, 0x2c, 0x3c, 0x0d, 0x1d, 0x2d, 0x3d,
     0x0e, 0x1e, 0x2e, 0x3e, 0x0f, 0x1f, 0x2f, 0x3f)
# inverse of P-box
P1 = (0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c,
      0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c,
      0x01, 0x05, 0x09, 0x0d, 0x11, 0x15, 0x19, 0x1d,
      0x21, 0x25, 0x29, 0x2d, 0x31, 0x35, 0x39, 0x3d,
      0x02, 0x06, 0x0a, 0x0e, 0x12, 0x16, 0x1a, 0x1e,
      0x22, 0x26, 0x2a, 0x2e, 0x32, 0x36, 0x3a, 0x3e,
      0x03, 0x07, 0x0b, 0x0f, 0x13, 0x17, 0x1b, 0x1f,
      0x23, 0x27, 0x2b, 0x2f, 0x33, 0x37, 0x3b, 0x3f)


def main():
    a = 0xffffffffffffffff
    k = 0x0
    rK = Keyschedule(k)
    print("Encrypted text", hex(encrypt(rK, a)))
    print("Decrypted text", hex(decrypt(rK, encrypt(rK, a))))
    print("Check: ", a == decrypt(rK, encrypt(rK, a)))
    # done all test

def Keyschedule(k: int) -> list:  # k - V80
    res = []  # init
    for i in range(32):
        res.append(k >> 16)
        # shift (0x7ffff = pow(2, 19) - 1)
        k = ((k & 0x7ffff) << 61) ^ (k >> 19)
        # S-box (0xfffffffffffffffffff = pow(2, 76) - 1)
        k = (S[k >> 76] << 76) ^ (k & 0xfffffffffffffffffff)
        # salt
        k ^= (i + 1) << 15
    return res

def Keyadd(k: int, a: int) -> int:
    return k ^ a

def NonLinear(a: int) -> int:
    """
    :param a: 64-bit vector
    :return: 64-bit vector
    """
    return (S[a >> 60] << 60) ^ (S[(a >> 56) & 0xf] << 56) ^ \
           (S[(a >> 52) & 0xf] << 52) ^ (S[(a >> 48) & 0xf] << 48) ^ \
           (S[(a >> 44) & 0xf] << 44) ^ (S[(a >> 40) & 0xf] << 40) ^ \
           (S[(a >> 36) & 0xf] << 36) ^ (S[(a >> 32) & 0xf] << 32) ^ \
           (S[(a >> 28) & 0xf] << 28) ^ (S[(a >> 24) & 0xf] << 24) ^ \
           (S[(a >> 20) & 0xf] << 20) ^ (S[(a >> 16) & 0xf] << 16) ^ \
           (S[(a >> 12) & 0xf] << 12) ^ (S[(a >> 8) & 0xf] << 8) ^ \
           (S[(a >> 4) & 0xf] << 4) ^ (S[a & 0xf])

def InverseNonLinear(a: int) -> int:
    """
    :param a: 64-bit vector
    :return: 64-bit vector
    """
    return (S1[a >> 60] << 60) ^ (S1[(a >> 56) & 0xf] << 56) ^ \
           (S1[(a >> 52) & 0xf] << 52) ^ (S1[(a >> 48) & 0xf] << 48) ^ \
           (S1[(a >> 44) & 0xf] << 44) ^ (S1[(a >> 40) & 0xf] << 40) ^ \
           (S1[(a >> 36) & 0xf] << 36) ^ (S1[(a >> 32) & 0xf] << 32) ^ \
           (S1[(a >> 28) & 0xf] << 28) ^ (S1[(a >> 24) & 0xf] << 24) ^ \
           (S1[(a >> 20) & 0xf] << 20) ^ (S1[(a >> 16) & 0xf] << 16) ^ \
           (S1[(a >> 12) & 0xf] << 12) ^ (S1[(a >> 8) & 0xf] << 8) ^ \
           (S1[(a >> 4) & 0xf] << 4) ^ (S1[a & 0xf])


def Linear(a: int) -> int:
    """
    :param a: 64-bit vector
    :return: 64-bit vector
    """
    output = 0
    for i in range(64):
        output ^= (((a >> i) & 0b1) << P[i])
    return output

def InserseLinear(a: int) -> int:
    """
    :param a: 64-bit vector
    :return: 64-bit vector
    """
    output = 0
    for i in range(64):
        output ^= (((a >> i) & 0b1) << P1[i])
    return output

def rFuncE(k: int, a: int) -> int:
    return Linear(NonLinear(Keyadd(k, a)))

def rFuncD(k: int, a: int) -> int:
    return InverseNonLinear(InserseLinear(Keyadd(k, a)))

def encrypt(k: list, a: int) -> int:
    """
    :param k: 64-bit vector
    :param a: 64-bit vector
    :return: 64-bit vector
    """
    for i in range(31):
        data = rFuncE(k[i], a)
        a = data
    return Keyadd(k[31], a)

def decrypt(k: list, a: int) -> int:
    for i in range(31, 0, -1):
        data = rFuncD(k[i], a)
        a = data
    return Keyadd(k[0], a)


if __name__ == '__main__':
    main()
