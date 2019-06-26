# Portions Copyright (c) 2016 kste
# Portions Copyright (c) 2018 Michael Toutonghi
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

'''VerusHash hash function.'''

import itertools
import copy

MPAR = 1
ROUNDS = 5
AES_ROUNDS = 2

# AES S-box
S = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
      0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
     [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
      0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
     [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
      0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
     [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
      0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
     [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
      0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
     [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
      0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
     [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
      0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
     [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
      0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
     [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
      0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
     [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
      0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
     [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
      0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
     [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
      0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
     [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
      0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
     [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
      0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
     [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
      0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
     [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
      0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]

RC0 = [0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
       0x00000000000000000000000000000000, 0x00000000000000000000000000000000]

RC2 = [0x0684704ce620c00ab2c5fef075817b9d, 0x8b66b4e188f3a06b640f6ba42f08f717,
       0x3402de2d53f28498cf029d609f029114, 0x0ed6eae62e7b4f08bbf3bcaffd5b4f79,
       0xcbcfb0cb4872448b79eecd1cbe397044, 0x7eeacdee6e9032b78d5335ed2b8a057b,
       0x67c28f435e2e7cd0e2412761da4fef1b, 0x2924d9b0afcacc07675ffde21fc70b3b,
       0xab4d63f1e6867fe9ecdb8fcab9d465ee, 0x1c30bf84d4b7cd645b2a404fad037e33,
       0xb2cc0bb9941723bf69028b2e8df69800, 0xfa0478a6de6f55724aaa9ec85c9d2d8a,
       0xdfb49f2b6b772a120efa4f2e29129fd4, 0x1ea10344f449a23632d611aebb6a12ee,
       0xaf0449884b0500845f9600c99ca8eca6, 0x21025ed89d199c4f78a2c7e327e593ec,
       0xbf3aaaf8a759c9b7b9282ecd82d40173, 0x6260700d6186b01737f2efd910307d6b,
       0x5aca45c22130044381c29153f6fc9ac6, 0x9223973c226b68bb2caf92e836d1943a,
       0xd3bf9238225886eb6cbab958e51071b4, 0xdb863ce5aef0c677933dfddd24e1128d,
       0xbb606268ffeba09c83e48de3cb2212b1, 0x734bd3dce2e4d19c2db91a4ec72bf77d,
       0x43bb47c361301b434b1415c42cb3924e, 0xdba775a8e707eff603b231dd16eb6899,
       0x6df3614b3c7559778e5e23027eca472c, 0xcda75a17d6de7d776d1be5b9b88617f9,
       0xec6b43f06ba8e9aa9d6c069da946ee5d, 0xcb1e6950f957332ba25311593bf327c1,
       0x2cee0c7500da619ce4ed0353600ed0d9, 0xf0b1a5a196e90cab80bbbabc63a4a350,
       0xae3db1025e962988ab0dde30938dca39, 0x17bb8f38d554a40b8814f3a82e75b442,
       0x34bb8a5b5f427fd7aeb6b779360a16f6, 0x26f65241cbe5543843ce5918ffbaafde,
       0x4ce99a54b9f3026aa2ca9cf7839ec978, 0xae51a51a1bdff7be40c06e2822901235,
       0xa0c1613cba7ed22bc173bc0f48a659cf, 0x756acc03022882884ad6bdfde9c59da1]


# get padded hex for single byte
def hexbyte(x):
    return hex(x)[2:].zfill(2)


# print list of bytes in hex
def ps(s):
    return "".join([hexbyte(x) for x in s])


# print state
def printstate(s):
    for i in range(4):
        if len(s) == 4:
            q = [s[0][i], s[0][i+4], s[0][i+8], s[0][i+12],
                 s[1][i], s[1][i+4], s[1][i+8], s[1][i+12],
                 s[2][i], s[2][i+4], s[2][i+8], s[2][i+12],
                 s[3][i], s[3][i+4], s[3][i+8], s[3][i+12]]
        else:
            q = [s[0][i], s[0][i+4], s[0][i+8], s[0][i+12],
                 s[1][i], s[1][i+4], s[1][i+8], s[1][i+12]]
        print(" ".join([hexbyte(x) for x in q]))
        # print q
    print("")


# xor two lists element-wise
def xor(x, y):
    return [x[i] ^ y[i] for i in range(16)]


# apply a single S-box
def sbox(x):
    return S[(x >> 4)][x & 0xF]


def aesenc_emu(s16, rk16):
    v = [[0 for i in range(4)] for i in range(4)]
    for i in range(16):
        v[((i >> 2) + 4 - (i & 3)) & 3][i & 3] = sbox(s16[i])

    for i in range(4):
        t = v[i][0]
        u = v[i][0] ^ v[i][1] ^ v[i][2] ^ v[i][3]
        v[i][0] ^= u ^ XT(v[i][0] ^ v[i][1])
        v[i][1] ^= u ^ XT(v[i][1] ^ v[i][2])
        v[i][2] ^= u ^ XT(v[i][2] ^ v[i][3])
        v[i][3] ^= u ^ XT(v[i][3] ^ t)

    for i in range(16):
        s16[i] = v[i >> 2][i & 3] ^ rk16[i]

    return s16


# consider 4 consecutive entries as 32-bit values and shift each of them to the left
def shift32(x):
    # make list of 32-bit elements
    w = [((x[i] << 24) ^ (x[i+1] << 16) ^ (x[i+2] << 8) ^ x[i+3]) << 1 for i in [0, 4, 8, 12]]
    return list(itertools.chain(*[[(q >> 24) & 0xFF, (q >> 16) & 0xFF,
                                   (q >> 8) & 0xFF, (q >> 0) & 0xFF]
                                  for q in w]))


# linear mixing for Haraka-512/256
def mix512(s):
    return [s[0][12:16] + s[2][12:16] + s[1][12:16] + s[3][12:16],
            s[2][0:4] + s[0][0:4] + s[3][0:4] + s[1][0:4],
            s[2][4:8] + s[0][4:8] + s[3][4:8] + s[1][4:8],
            s[0][8:12] + s[2][8:12] + s[1][8:12] + s[3][8:12]]


# linear mixing for Haraka-256/256
def mix256(s):
    return [s[0][0:4] + s[1][0:4] + s[0][4:8] + s[1][4:8],
            s[0][8:12] + s[1][8:12] + s[0][12:16] + s[1][12:16]]


# convert RC to 16 words state
def convRC(rc):
    return [(rc >> (i << 3) & 0xff) for i in range(16)]


# Haraka-512/256
def haraka512256(msg, rc=RC0):
    # obtain state from msg input and set initial rcon
    s = [msg[i:i+16] for i in [0, 16, 32, 48]]
    rcon = [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]

    # apply round functions
    for t in range(ROUNDS):
        # first we do AES_ROUNDS of AES rounds and update the round constant each time
        for m in range(AES_ROUNDS):
            s = [aesenc_emu(s[i], convRC(rc[4*t*AES_ROUNDS + 4*m + i])) for i in range(4)]

        # now apply mixing
        s = mix512(s)

    # apply feed-forward
    s = [xor(s[i], msg[16*i:16*(i+1)]) for i in range(4)]

    # truncation
    return s[0][8:] + s[1][8:] + s[2][0:8] + s[3][0:8]


# Haraka-256/256
def haraka256256(msg, rc=RC0):
    # obtain state from msg input and set initial rcon
    s = [msg[i:i+16] for i in [0, 16]]
    rcon = [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]

    # apply round functions
    for t in range(ROUNDS):
        # first we do AES_ROUNDS of AES rounds and update the round constant each time
        for m in range(AES_ROUNDS):
            s = [aesenc_emu(s[i], convRC(rc[2*t*AES_ROUNDS + 2*m + i])) for i in range(2)]
            rcon = shift32(rcon)

        # now apply mixing
        s = mix256(s)

    # apply feed-forward
    s = [xor(s[i], msg[16*i:16*(i+1)]) for i in range(2)]

    # truncation
    return list(itertools.chain(*s))


# verus_hash
def verus_hash(msg):
    buf = [0] * 64
    length = len(msg)
    for i in range(0, length, 32):
        clen = min(32, length - i)
        buf[32:64] = [b for b in msg[i:i + clen]] + [0] * (32 - clen)
        buf[0:32] = haraka512256(buf, rc=RC0)
    return bytes(buf[0:32])


# verus_hash
def verus_hash2(msg):
    buf = [0] * 64
    length = len(msg)
    for i in range(0, length, 32):
        clen = min(32, length - i)
        buf[32:64] = [b for b in msg[i:i + clen]] + [0] * (32 - clen)
        buf[0:32] = haraka512256(buf, rc=RC2)
    return bytes(buf[0:32])


# Emulated intrinsics to support verus_clhash
def clmul(m, n):
    return n and (n & 1) * m ^ clmul(m << 1, n >> 1)


def _mm_clmulepi64_si128_emu_0x10(a, b):
    return clmul(a & 0xffffffffffffffff, ((b & 0xffffffffffffffff0000000000000000) >> 64))


def _mm_unpacksi128_si16_emu(a, pos):
    r = (a >> (pos << 4)) & 0xffff
    if (r & 0x8000):
        r = r - 0x10000
    return r


# multiplies one 16 bit signed value unpacked from a 128 bit value
def _mm_1mulhrs_epi16_emu(a, b, pos):
    return ((_mm_unpacksi128_si16_emu(a, pos) *
             _mm_unpacksi128_si16_emu(b, pos) + 0x4000) >> 15) & 0xffff


def _mm_mulhrs_epi16_emu(a, b):
    return sum([_mm_1mulhrs_epi16_emu(a, b, i) << (i << 4) for i in range(8)])


def _mm_set_epi64x_emu(hi, lo):
    return hi << 64 | lo


def _mm_cvtsi64_si128_emu(lo):
    return lo


def _mm_cvtsi128_si64_emu(a):
    return a & 0xffffffffffffffff


def _mm_cvtsi128_si32_emu(a):
    return a & 0xffffffff


def _mm_cvtsi32_si128_emu(lo):
    return lo


def _mm_setr_epi8_emu(l16):
    return sum([l16[i] << (i << 3) for i in range(16)])


def _mm_srli_si128_emu(a, imm8):
    shift = imm8 & 0xff
    if (shift > 15):
        shift = 16
    return a >> (shift << 3)


def _mm_xor_si128_emu(a, b):
    return a ^ b


def _mm_shuffle_epi8_emu(a, b):
    inp = [(a >> (i << 3) & 0xff) for i in range(16)]
    result = int(0)
    for i, idx in zip(range(16), [(b >> (j << 3) & 0xff) for j in range(16)]):
        if not idx & 0x80:
            result |= (inp[idx & 0xf] << (i << 3))
    return result


def XT(x):
    return (((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b)) & 0xff


def AES2(_s0, _s1, rci, rc=RC2):
    s0 = [(_s0 >> (i << 3)) & 0xff for i in range(16)]
    s1 = [(_s1 >> (i << 3)) & 0xff for i in range(16)]
    s0 = aesenc_emu(s0, convRC(rc[rci]))
    s1 = aesenc_emu(s1, convRC(rc[rci + 1]))
    s0 = aesenc_emu(s0, convRC(rc[rci + 2]))
    s1 = aesenc_emu(s1, convRC(rc[rci + 3]))
    return sum([(s & 0xff) << (i << 3) for s, i in zip(s0, range(16))]), sum([(s & 0xff) << (i << 3) for s, i in zip(s1, range(16))])


def _mm_unpacklo_epi32_emu(s0, s1):
    return (s0 & 0xffffffff) | ((s0 & 0xffffffff00000000) << 32) | ((s1 & 0xffffffff) << 32) | ((s1 & 0xffffffff00000000) << 64)


def _mm_unpackhi_epi32_emu(s0, s1):
    r0 = (s0 >> 64) & 0xffffffffffffffff
    r1 = (s1 >> 64) & 0xffffffffffffffff
    return (r0 & 0xffffffff) | ((r0 & 0xffffffff00000000) << 32) | ((r1 & 0xffffffff) << 32) | ((r1 & 0xffffffff00000000) << 64)


def MIX2(s0, s1):
    return _mm_unpacklo_epi32_emu(s0, s1), _mm_unpackhi_epi32_emu(s0, s1)


def AES2_MIX2_EMU(s0, s1, rci, rc=RC2):
    r0, r1 = AES2(s0, s1, rci, rc)
    return MIX2(r0, r1)


# verus intermediate hash extra
def __verusclmulwithoutreduction64alignedrepeat_port(randomsource, buf, keyMask):
    # divide key mask by 16 from bytes to __m128i
    keyMask >>= 4

    acc = randomsource[keyMask + 2]

    for i in range(32):
        selector = _mm_cvtsi128_si64_emu(acc)

        # get two random locations in the key, which will be mutated and swapped
        prand = ((selector >> 5) & keyMask)
        prandex = ((selector >> 32) & keyMask)

        # select random start and order of pbuf processing
        pbuf = (selector & 3)

        path = selector & 0x1c

        if (path == 0):
            temp1 = randomsource[prandex]
            temp2 = buf[pbuf - (((pbuf & 1) << 1) - 1)]
            add1 = _mm_xor_si128_emu(temp1, temp2)
            clprod1 = _mm_clmulepi64_si128_emu_0x10(add1, add1)
            acc = _mm_xor_si128_emu(clprod1, acc)

            tempa1 = _mm_mulhrs_epi16_emu(acc, temp1)
            tempa2 = _mm_xor_si128_emu(tempa1, temp1)

            temp12 = randomsource[prand]
            randomsource[prand] = tempa2

            temp22 = buf[pbuf]
            add12 = _mm_xor_si128_emu(temp12, temp22)
            clprod12 = _mm_clmulepi64_si128_emu_0x10(add12, add12)
            acc = _mm_xor_si128_emu(clprod12, acc)

            tempb1 = _mm_mulhrs_epi16_emu(acc, temp12)
            tempb2 = _mm_xor_si128_emu(tempb1, temp12)
            randomsource[prandex] = tempb2

        elif (path == 4):
            temp1 = randomsource[prand]
            temp2 = buf[pbuf]
            add1 = _mm_xor_si128_emu(temp1, temp2)
            clprod1 = _mm_clmulepi64_si128_emu_0x10(add1, add1)
            acc = _mm_xor_si128_emu(clprod1, acc)
            clprod2 = _mm_clmulepi64_si128_emu_0x10(temp2, temp2)
            acc = _mm_xor_si128_emu(clprod2, acc)

            tempa1 = _mm_mulhrs_epi16_emu(acc, temp1)
            tempa2 = _mm_xor_si128_emu(tempa1, temp1)

            temp12 = randomsource[prandex]
            randomsource[prandex] = tempa2

            temp22 = buf[pbuf - (((pbuf & 1) << 1) - 1)]
            add12 = _mm_xor_si128_emu(temp12, temp22)
            acc = _mm_xor_si128_emu(add12, acc)

            tempb1 = _mm_mulhrs_epi16_emu(acc, temp12)
            tempb2 = _mm_xor_si128_emu(tempb1, temp12)
            randomsource[prand] = tempb2

        elif (path == 8):
            temp1 = randomsource[prandex]
            temp2 = buf[pbuf]
            add1 = _mm_xor_si128_emu(temp1, temp2)
            acc = _mm_xor_si128_emu(add1, acc)

            tempa1 = _mm_mulhrs_epi16_emu(acc, temp1)
            tempa2 = _mm_xor_si128_emu(tempa1, temp1)

            temp12 = randomsource[prand]
            randomsource[prand] = tempa2

            temp22 = buf[pbuf - (((pbuf & 1) << 1) - 1)]
            add12 = _mm_xor_si128_emu(temp12, temp22)
            clprod12 = _mm_clmulepi64_si128_emu_0x10(add12, add12)
            acc = _mm_xor_si128_emu(clprod12, acc)
            clprod22 = _mm_clmulepi64_si128_emu_0x10(temp22, temp22)
            acc = _mm_xor_si128_emu(clprod22, acc)

            tempb1 = _mm_mulhrs_epi16_emu(acc, temp12)
            tempb2 = _mm_xor_si128_emu(tempb1, temp12)
            randomsource[prandex] = tempb2

        elif (path == 0xc):
            temp1 = randomsource[prand]
            temp2 = buf[pbuf - (((pbuf & 1) << 1) - 1)]
            add1 = _mm_xor_si128_emu(temp1, temp2)

            acc = _mm_xor_si128_emu(add1, acc)

            dividend = _mm_cvtsi128_si64_emu(acc)
            modadd = 0
            modmul = 1
            if (dividend & 0x8000000000000000):
                dividend = -(dividend - 0x10000000000000000)
                modadd = 0x100000000
                modmul = -1

            # cannot be zero here
            divisor = selector & 0xffffffff
            if (divisor & 0x80000000):
                divisor = -(divisor - 0x100000000)

            modulo = (dividend % divisor - modadd) * modmul

            acc = _mm_xor_si128_emu(modulo, acc)

            tempa1 = _mm_mulhrs_epi16_emu(acc, temp1)
            tempa2 = _mm_xor_si128_emu(tempa1, temp1)

            if (dividend & 1):
                temp12 = randomsource[prandex]
                randomsource[prandex] = tempa2

                temp22 = buf[pbuf]
                add12 = _mm_xor_si128_emu(temp12, temp22)
                clprod12 = _mm_clmulepi64_si128_emu_0x10(add12, add12)
                acc = _mm_xor_si128_emu(clprod12, acc)
                clprod22 = _mm_clmulepi64_si128_emu_0x10(temp22, temp22)
                acc = _mm_xor_si128_emu(clprod22, acc)

                tempb1 = _mm_mulhrs_epi16_emu(acc, temp12)
                tempb2 = _mm_xor_si128_emu(tempb1, temp12)
                randomsource[prand] = tempb2
            else:
                tempb3 = randomsource[prandex]
                randomsource[prandex] = tempa2
                randomsource[prand] = tempb3

        elif (path == 0x10):
            # a few AES operations
            temp1 = buf[pbuf - (((pbuf & 1) << 1) - 1)]
            temp2 = buf[pbuf]

            temp1, temp2 = AES2_MIX2_EMU(temp1, temp2, prand, randomsource)
            temp1, temp2 = AES2_MIX2_EMU(temp1, temp2, prand + 4, randomsource)
            temp1, temp2 = AES2_MIX2_EMU(temp1, temp2, prand + 8, randomsource)

            acc = _mm_xor_si128_emu(temp1, acc)
            acc = _mm_xor_si128_emu(temp2, acc)

            tempa1 = randomsource[prand]
            tempa2 = _mm_mulhrs_epi16_emu(acc, tempa1)
            tempa3 = _mm_xor_si128_emu(tempa1, tempa2)

            tempa4 = randomsource[prandex]
            randomsource[prandex] = tempa3
            randomsource[prand] = tempa4

        elif (path == 0x14):
            # we'll just call this one the monkins loop, inspired by Chris
            buftmp = pbuf - (((pbuf & 1) << 1) - 1)

            rounds = (selector >> 61) & 7    # loop randomly between 1 and 8 times
            rc = prand
            aesround = 0

            for j in range(rounds, -1, -1):
                if (selector & ((0x10000000 << j) & 0xffffffff)
                    if j != 3
                        else selector & 0xffffffff80000000):
                            onekey = randomsource[rc]
                            rc += 1
                            temp2 = buf[pbuf] if j & 1 else buf[buftmp]
                            add1 = _mm_xor_si128_emu(onekey, temp2)
                            clprod1 = _mm_clmulepi64_si128_emu_0x10(add1, add1)
                            acc = _mm_xor_si128_emu(clprod1, acc)
                else:
                    onekey = randomsource[rc]
                    rc += 1
                    temp2 = buf[buftmp] if j & 1 else buf[pbuf]
                    roundidx = aesround << 2
                    aesround += 1
                    onekey, temp2 = AES2_MIX2_EMU(onekey, temp2, rc + roundidx, randomsource)

                    acc = _mm_xor_si128_emu(onekey, acc)
                    acc = _mm_xor_si128_emu(temp2, acc)

            tempa1 = randomsource[prand]
            tempa2 = _mm_mulhrs_epi16_emu(acc, tempa1)
            tempa3 = _mm_xor_si128_emu(tempa1, tempa2)

            tempa4 = randomsource[prandex]
            randomsource[prandex] = tempa3
            randomsource[prand] = tempa4

        elif (path == 0x18):
            temp1 = buf[pbuf - (((pbuf & 1) << 1) - 1)]
            temp2 = randomsource[prand]
            add1 = _mm_xor_si128_emu(temp1, temp2)
            clprod1 = _mm_clmulepi64_si128_emu_0x10(add1, add1)
            acc = _mm_xor_si128_emu(clprod1, acc)

            tempa1 = _mm_mulhrs_epi16_emu(acc, temp2)
            tempa2 = _mm_xor_si128_emu(tempa1, temp2)

            tempb3 = randomsource[prandex]
            randomsource[prandex] = tempa2
            randomsource[prand] = tempb3

        else:
            temp1 = buf[pbuf]
            temp2 = randomsource[prandex]
            add1 = _mm_xor_si128_emu(temp1, temp2)
            clprod1 = _mm_clmulepi64_si128_emu_0x10(add1, add1)
            acc = _mm_xor_si128_emu(clprod1, acc)

            tempa1 = _mm_mulhrs_epi16_emu(acc, temp2)
            tempa2 = _mm_xor_si128_emu(tempa1, temp2)

            tempa3 = randomsource[prand]
            randomsource[prand] = tempa2

            acc = _mm_xor_si128_emu(tempa3, acc)

            tempb1 = _mm_mulhrs_epi16_emu(acc, tempa3)
            tempb2 = _mm_xor_si128_emu(tempb1, tempa3)
            randomsource[prandex] = tempb2

    return acc


def lazyLengthHash_port(keylength, length):
    lengthvector = _mm_set_epi64x_emu(keylength, length)
    clprod1 = _mm_clmulepi64_si128_emu_0x10(lengthvector, lengthvector)
    return clprod1


# modulo reduction to 64-bit value. The high 64 bits contain garbage, see precompReduction64
def precompReduction64_si128_port(A):
    C = _mm_cvtsi64_si128_emu((1 << 4) + (1 << 3) + (1 << 1) + (1 << 0))
    Q2 = _mm_clmulepi64_si128_emu_0x10(C, A)
    Q3 = _mm_shuffle_epi8_emu(_mm_setr_epi8_emu([0, 27, 54, 45, 108, 119, 90, 65,
                                                 216, 195, 238, 245, 180, 175, 130, 153]),
                              _mm_srli_si128_emu(Q2, 8))
    Q4 = _mm_xor_si128_emu(Q2, A)
    return _mm_xor_si128_emu(Q3, Q4)


def precompReduction64_port(A):
    return _mm_cvtsi128_si64_emu(precompReduction64_si128_port(A))


# intermediate hash in verush_hash2b
def verus_clhash(key, msg):
    # convert msg into an array of 4 128 bit entries composed of the first 64 bytes
    acc = __verusclmulwithoutreduction64alignedrepeat_port(key, [_mm_setr_epi8_emu(msg[0:16]),
                                                           _mm_setr_epi8_emu(msg[16:32]),
                                                           _mm_setr_epi8_emu(msg[32:48]),
                                                           _mm_setr_epi8_emu(msg[48:64])], 8191)
    acc = _mm_xor_si128_emu(acc, lazyLengthHash_port(1024, 64))
    return precompReduction64_port(acc)


# finalize the 2b hash
def finalizehash2b(key, buf):
    intermediate = verus_clhash(key, buf)
    intlist = [(intermediate >> (j << 3) & 0xff) for j in range(8)]

    buf[47:55] = intlist[0:8]
    buf[55:63] = intlist[0:8]
    buf[63] = intlist[0]

    # run the intermediate clhash
    # run the final hash with the key determined by the intermediate
    idx = intermediate & 0x1ff
    buf[0:32] = haraka512256(buf, rc=key[idx:idx+40])
    return buf[0:32]


# verus_hash 2b
def verus_hash2b(msg):
    buf = [0] * 64
    key = [0 for i in range(552)]
    length = len(msg)
    for i in range(0, length, 32):
        clen = min(32, length - i)
        buf[32:64] = [b for b in msg[i:i + clen]] + [0] * (32 - clen)
        # when at the end, finalize with 2b
        if (clen < 32):
            # get large key of 128 bit entries from haraka256 chained inputs
            nextKey = buf[0:32]
            for i in range(0, 552, 2):
                nextKey = haraka256256(nextKey, rc=RC2)
                key[i] = _mm_setr_epi8_emu(nextKey[0:16])
                key[i + 1] = _mm_setr_epi8_emu(nextKey[16:32])

            # prepare buffer for intermediate hash
            buf[47:63] = buf[0:16]
            buf[63] = buf[0]

            intermediate = verus_clhash(key, buf)
            intlist = [(intermediate >> (j << 3) & 0xff) for j in range(8)]

            buf[47:55] = intlist[0:8]
            buf[55:63] = intlist[0:8]
            buf[63] = intlist[0]

            # run the intermediate clhash
            # run the final hash with the key determined by the intermediate
            idx = intermediate & 0x1ff
            buf[0:32] = haraka512256(buf, rc=key[idx:idx+40])
        else:
            # buf[0:32] = haraka512256(buf, rc=RC2)
            buf[0:32] = haraka512256(buf, rc=RC2)
    return bytes(buf[0:32])


def main():
    # set some message bytes
    m = [i for i in range(64)]

    test_header = [0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x40, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    test_verusv2_expected = '73729aa8e3385c68ac707950256ff4d5f0ee4c40a669ef249ed05832976a74bb'

    s = "Test1234"
    ary = []
    ary.extend(map(ord, s))

    # print Verus Hash output
    print("= test string = ")
    print(s + "\n")
    print("= verus_hash begins = ")

    op = verus_hash(bytes(ary))
    print("= verus_hash v1 complete - output = ")
    print(ps(op) + "\n")

    op = verus_hash2(bytes(ary))
    print("= verus_hash v2 complete - output = ")
    print(ps(op) + "\n")

    # block test
    print("= test_header - expected hash =")
    print(test_verusv2_expected)
    op = verus_hash2b(bytes(test_header))
    print("= verus_hash 2b complete - output = ")
    print(ps(op) + "\n")

    # clhash test
    print("= test finalize2b =")
    test_buf = [0x0c, 0x4b, 0x23, 0x67, 0x8e, 0x9d, 0xc3, 0x5e,
                0xaa, 0xed, 0x49, 0x3e, 0x32, 0x27, 0x3b, 0x24,
                0x3b, 0xae, 0xc9, 0x7b, 0x9a, 0xcc, 0x02, 0x72,
                0x38, 0x61, 0xb0, 0xc6, 0x58, 0x30, 0x23, 0x8e,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c,
                0x4b, 0x23, 0x67, 0x8e, 0x9d, 0xc3, 0x5e, 0xaa,
                0xed, 0x49, 0x3e, 0x32, 0x27, 0x3b, 0x24, 0x0c]
    test_key = [0xfa8b8a8a9693e26ba2d0b99c41af1bdf, 0x297f44802cec860f6d04f70f68e1243a, 0x93741d84ca982e871861a0a0311ba899, 0x9b9287fbd1fc6640978b956558c8e239, 0x32adc94283d0ea0a8a73a38fe7b7156b, 0x0614aeb1017ff2280513a87927f30b50, 0x734481ab4d91ca0ba9c1372348236d70, 0x0b3cf104afda6c4da42e9aca9fef7648, 0xb847395c764f36d81465de42e2a0c65c, 0x0090ce808194b48c41d32c3c0b29540a, 0x15ff8a58f9ddb2047365383ceea6a5dc, 0x3fdfc8b008c1735fce558355d7aca316, 0xec2ade0ff1716e56ae2b47c2fa9bd505, 0x0faf3a735005542e7e72ce7e975993ca, 0xfa6723035f065084db7027d606055f64, 0x29f5d7e8b7b511899852d5e155b25451, 0x35dedcdea40a0709b230ce9f093ae35f, 0x193c22e6c44070bad51d1d49b658309d, 0x66685593c6ab2d30244af741545210c0, 0x95813e97546de39ca7e51503f24ac611, 0xf511cb2edb5cafa6b176e58ae550b957, 0x1f8b4ab58796899ea97b7bd98b69fc98, 0xd67321384d960fab43c91ebed3150610, 0xe3e51762a63a12a004ded37ce7acb6de, 0xaa0da8bd71ba510d3d0bd77552c6aa88, 0x80f39af918c6829bcdc1eb90a18265d9, 0xe2f60e6826c20a3024e5b4148fcbc47c, 0x9c31d478b10839748f8a787e910fcb62, 0x3f94b669a9aa8fc2785b8e5ace93216a, 0x45e193bb0de211f21663b8d7fdb8ced0, 0x6df3b7c5a31715c61f8ec2ee367e2112, 0x716313e378ee242478d040c1e91abb53, 0xcb6150f42a3f55018cba3c5704b73288, 0xeebdd6b20ae8f6686ec527d041648b67, 0x9543fee8dd5c4a360364fecd71fb6c0d, 0xf9a5488d725fb277f7b7111c9b93d118, 0x15be7a58c4e78bf55debbb9d2b72bc39, 0xb183240af2cd02e21020dfd988e8e89c, 0x8e4590955816bd1edc310657cd8aa6c1, 0x7ca0cc1e6d1297afe4abfcb250236426, 0x150463ffe5d6f3b359fa7e433815468b, 0x0ec5dd9646671a8aa16fc99744219362, 0x97023c57b9b94bad7ab99f9ea79a3cf3, 0x970872c30faf21c45045bb28c21871ef, 0xba1cedbdac290e1d85d01a9c54621a0f, 0xb59a7ebf72e772b801e285c1eafe85f5, 0xe4b8d86a07aeee8ad2eb852264c8a902, 0x5858af94e492c0572c3a64ea17af5abd, 0x8d6f9b1bb109c95ae73570b58ceb8662, 0xaa87e784ad61b58dd0beb9c78f66d015, 0x69cee55e3231eacd8f9ba6237a8db66a, 0x34b05f091dddaf8a2015570a5224eda7, 0xffcd5961164e9956c6a2fcc7fbcb7e5f, 0x799ef29ef5be69fcafeb39c797d0e24c, 0x8c0c647104f4530fa1228b487db4d4de, 0x3acc02339c549e9db60e60c9ae419a2a, 0xc7006597fff960d97348b780717ff0ca, 0xc365c8ff09623f856225d717238501ec, 0x2865a4840c6322d76b36c0e9b3cbac2a, 0xb3ff6da7de7e2becdf9a805f07b566f7, 0x1bb4b77c53b403ac0e91f6faf20bc71e, 0x14e23402f1151b46496d422bc204bc6a, 0x0016824bab22825b322e2430db2585c7, 0xb25737f5b018f352c45bb385c1d1df54, 0x24974b68b70ab04d7e0a3a9cb7ffe99b, 0xf643c71c39818da5792a4b7535872b09, 0x1c26f3c00fb432082d130e44019738b1, 0x0d2ba8510c6d02070da9619be3c1db73, 0xe3b846f61b0939db6493ce6a7ba550d1, 0xfd14b154db67e33466234c39ea4c7d72, 0x83370a56f42c4202060c06e431b48bb2, 0x46da1387ac1f0ec7ae388bb061f8a111, 0xf6c85c45caac4e1d47dbb06853446a0f, 0xae45701e6993d78627a2c9700ed57b81, 0x23e1bf81ce8459fecf63f074f465bf05, 0xd4632e566e9a190298611dae56453d58, 0x058e36c1ced28f4b01cd30c9c53d9652, 0x96caea66437b157675f8a847062f80fa, 0xc0455b7a337145faceb4c2bbd80648d8, 0xa31053c8ba9fe2df10912ec512faa25b, 0x0bdb11f4d616cf393bc540f07b2f3bf4, 0x12e393af425ae6f7b9415e4f2e7495a9, 0xdf8aa122066ee32c80f49499bc9556c3, 0xe7de712447af8b4a3909e0766ca069e7, 0x6445dcacc77bf2cb4e0dec82f07fe114, 0x9febdea0266644fe81634f3786a3c48b, 0xbb379f6dc4144564520007b0fdd23167, 0x9dc9354b7b046fc59c7f8926267d18ec, 0xaecca486643c4157784cfc54b6886c84, 0xe06642a30c84cba8ac1ec83198249560, 0x9aec17d1e4ad6a2e730d892a68d5381d, 0x0c2e068109cf226bdf9e5a9e318a871b, 0xd9cecafaebc47a14ebce46b5ecd7dbda, 0x142a8c73c169872e7cd7221b50a4d515, 0xa29b014ddaf7a4aa108617b742fd1161, 0x52a55f87a82a390ca9c43d605a7938e6, 0x87d62a52286f75ce57b590da18edd2b4, 0x037f6b3ba1dd493dbfadd00e9e145c6a, 0x8bbd44b4a3a1ba1e79cbbc8ba8e68eea, 0x301dc85b31a2c07ef0edd196772e27a9, 0x4cd04e2f7127867be5250f48538d18b3, 0x1137f891265458c1f15de5e59448bb40, 0xd88d7bfc65e5254c03c0e4ad1e7f1f99, 0x77b25edeb9f727ad09f4e159f498f75b, 0xa64ad1b2668031971a8f0b812161969a, 0x827bd7c5b336592cd98186f96f6988ed, 0xa06c3dd154dbf12061a69d034645f3de, 0x020e7de0c8a6e3230f667eaa357ff9aa, 0x3532ebf9ca59e4e8ef5eefa9c1e818ca, 0x923a2ead4ed41d9551292385367949dc, 0xcc582c7ba743a53636082588b8ddbc96, 0x12249317e8b8c2a810576862bf78eb81, 0xdc76659b428564b0cc20a6e243d87bf4, 0xbf60cf6181e20d03347930ce3b63119a, 0x2313906f86756aaaded4c804d4c097d5, 0x8d3b9e33895f79e6aea7be927899cdd3, 0x21a85c934546b72f9cae7a2e44fee0f4, 0x9276e8191118f0e481d1dd584f025302, 0xbc737b87894213e83ad0cfaa5f0a2a31, 0x44b787fc5a1f128e6f2afe82851e6ecb, 0x394d2edb91138ff95d5131f01e9dee2a, 0x04607a44b2bb60e1e5fdd8fff434492a, 0xe5eb1cf3038b5d016983a55e449e06ad, 0xab4beb4231aac4f47a8a42632fc3b374, 0x0278578852b7e9362575989c7971c811, 0x950274ef56aa88845f05805d4fec1699, 0xa9a4ca84d60e8e0858675c63ed42506b, 0x30b176979db7a8cb10f57d9d2ad5aadb, 0x927bc15563893347f4c38de8fb5588a6, 0xfed80392f435289e6def34de6a905bc7, 0x12350fa03f540bd02da1d0ccb01edbdd, 0xc440fd4617d2719b05d53a67ddf5b172, 0x15c2e1cd2542c24d1eafdec0184611e6, 0xb198fcec2df30186e870efb1b0752b60, 0xb51fd370fa96969f83ffb63c14bce1ef, 0x08d53d28fb4805221cd3d8456bb425f1, 0x9d8eca2b7e544faf6ad85abff27078ce, 0x5e9303592320dcce926e7fdd9acb1e42, 0x57bf1141da9dd80689541ee790c35741, 0xf8d41c841f22f6ea9939f487c61e3767, 0x8c9ef4e56fd4e2fd91cf691bbcfe60a8, 0xfd14242f3a197a7575bb94baf2de76dd, 0xa7af72dff65aea3e77737f15937a4244, 0xd13a7d56279009327998833a832eaa98, 0x9154d68f5f6792d9fb2f324383744472, 0x7091ac4c2c5d6a60a34826fd40fabefd, 0x329983f6ef869bd47f2f93477967a310, 0xe30ee03b36a44859e18edb473d07ff71, 0x8b77338816dd07a059a160b5809b85c2, 0xa71ef64e7157b0ef23bb0c82a826720c, 0xcc986bb66fec828f3407c469bbdc2949, 0xb81d3ba43ebab7c3334431c644049ad1, 0x6b52e58631d1936eaa9f759ea2895ddb, 0x60f47e72fd6f02e41e2862ade57770be, 0xf758a3ee01e934f100d7f5a385b3dfb8, 0xdd1ce616531e77fb71f06ffa06783cc0, 0x7f0255e5b9c5b35ba4933762e27c7faf, 0x3af24a670e69cdc5c189e727f9b03e27, 0x447ebc332dbd8aa496e98232f35a1ef6, 0x16fba3216e44b6e298b2303a90108bf0, 0xc57d85735aa729ec30ddd1c9c85dd8a1, 0x4782ff860ab644499f5b477a5683ad75, 0x3d1fd4ea520ffea048050b374c8f80f8, 0x0dd42c1a5aa0090099d4c7326f4a2f01, 0x06fd230f0b96846c361d95e30d858cc2, 0xbecf16b69f097f9ea089d88d88b5c8f6, 0xebfe937fb12e6d44264b1d5360771159, 0xff95f25c27cb070947de21f900192478, 0x78f02ae1d80455ea41c7a7a7e3a1e53b, 0x9e6ad44ee895eedf7013a7b5243bdb72, 0x46931c27c3cd2efc6b1dae9ebd793581, 0x60142b4575bf644e8269e38ef49f752b, 0xd1433eac74dc041fa4a2ca99d9688f7b, 0x312377406c11ecc03f4ee1d8dcdadd2d, 0xe75bdb8fa1884ee279dce5f582aefc65, 0xa5f3d49b4ec3b9f18739fa217e6bb7e3, 0x39f7874a6efb68750f5bd5729be1419d, 0x2926cdf41cc2e6959e472e57d58fe08d, 0xc87be536fb9595040e989013b243186c, 0xcc35c6e7efe45f8746326721ea0fe13e, 0xcafc4396b55192c956285e93315837f9, 0xa6ede5b09205876e4be53ba7f425329f, 0x96b43d549d07ccc0918365e0a409d20f, 0x15025f4b375d43da400585cee17210e4, 0xd990a750c832d1e0a8cc012109bb028f, 0x15a9779cd1fc96763193f8ce103163d7, 0x852b96c4746a1e818e5b03aa5d9a07cd, 0x278767696f511bb1e6f55da5092f5454, 0x19e689f45a468ea27ac4ec619e4f1b63, 0xd61212816bb3f833756a2f3bb520aa66, 0x566f1d78b6e89e2f81f570ec5064c9b1, 0xae20f9851be85243e16be136f6a64333, 0x11630c06eba6c7461d1cf73e0dac6c94, 0xd960f7e6493e2743c11fc70e5d4a0ea6, 0x2cf4c52662e56493543c69b546ccd257, 0x9d979f86e18789ebe9a26ec7af11ceaf, 0x057b4d5f7dbddff4960dec57e339b701, 0x6e9f74cd977872f9537f3a41184ee130, 0x01d8332fb7217e494ad4607f1924d270, 0x88b81588dae8a5e71c75c73bb358e715, 0xca1e5bd5cc44cf15be9650cfd2b83002, 0x6f3dec94b7f95fe20ba3dcb1d50d6b43, 0x6b729b72185adc94ae6e5f2e924e6a2b, 0x79d42ad69101d0b5c92e4a9a25cc4bc3, 0x21460cd82d086d8fce1cc7a0f6a4d43a, 0x73dfe2bb0589fc73bd57f8589701013d, 0xf735c99713900b32a7d96065a1fdb1f6, 0xc3c043120afd68908f9f4ca1772272d3, 0xcccd67763ae0bdcc96522da735abc120, 0x82f55d5c8e59ca13934f572be4389b1a, 0x60c4f0a553e9bf93e87cd6b01a8194a2, 0xfce563e986c88aa907ebf19390c31b59, 0xed68e8e145b509e0a096f2ef8b6da094, 0x3e6a08312d4f05229544eee6966af3da, 0x3b3bdc33f5dd6d53e083416386426c55, 0xbf767ee2967ef8287fef6e2d19a5fbea, 0x4ebc0b840183b54ee54c067f3537aacc, 0xb03a7fe1dd7bb8747f0f1ac271b3d358, 0x2a0c3ff892272ff79c6ff603d22f2a3d, 0x80b127a643f22894df8faac7e749fc12, 0xd157c147bda5b7244755ca371c1d246d, 0x16836a3fadbda055a808eaa70c817716, 0x26737174b2f4bca7efc00c4bcfbf136f, 0x4ff7d1fa20389bd45f3d3dfdc4cb38a8, 0x9ff1579009bb999ba5f2ced19dd58527, 0x67b958008658a9b794243512bdf0b58a, 0x502c175e12e532861d8233def8bdd1b7, 0x01b5c1a370ad26b687f0439473a09269, 0x8eb263a0b971cfdbdcc50c40eba4ac95, 0x4125154e4e8043997be97213ef329a67, 0xdddf58a2b46514e8c81e2bef3796d23a, 0xc76b5cdddce755d4e89c9dbe484d3bfc, 0x54e821394b6091f28abca0057761199f, 0xcc2c31b60a8aebd4f43ba7f4b94f304a, 0xaf1919e68d51af0221fd67cd0d686e2b, 0x23a662e9c946dafe9081620a5fc8a488, 0x8c526ec7ce33f0e30dcae19cc4c68fcd, 0xf8a8cd307e6b6bfdbf205289528e96a0, 0x5fcfa6c1ec8292148703b8b50650e3f2, 0x6d5348299274294699c08b91583c86fe, 0x3cb6ed8626b07fa5ea9adde28c53c2c7, 0x89465649c81997e547a3064241a274ee, 0x8a27d9f877a57fafdda31ab5e45b3aa4, 0x6c8fc591869088b6eaeb3c00c198b8b4, 0x2f9d47401f4db9feac10c8371b66f04d, 0xd71e930ac7515d26e0641e3ee38c95b8, 0xb6b3f9570630e35656e61f59cecda68e, 0xb6edd2774383f90dc83152d43b009b4d, 0xba1be503a0ac114c0f9627faa19210f8, 0xe0ed3105759c68cbd6c399ffd844f672, 0x7f8364b225ef696835f942540f6f7e83, 0xdbcf378564e1c74f719f6ad331fcf053, 0x7629681f818c37fc387fc23d7b321d47, 0xeec783f429a476a346eacbce54d6665a, 0x540156ec5714dd889ac5c2628ef63ef3, 0xeb1b0d5ee49597d0ec7b18cd89e95718, 0x2d2360724722e1952de18bd24c249a38, 0x4d3cd8f2899904fad0ad347632ccaddd, 0x3a5f89e863ed78bf7e0a9a5c2b5be817, 0xe9a60de1b7f25a5cd11f5e1e67262c94, 0xfa59dc7c7c5ffa0c206b10f3f806351d, 0x5b74e04f52f4d8d55c2004655dfb34fb, 0x7bf564104dbddc9e23e818d388edb991, 0x250540dea0345a2ad43dbfd26adf9e3d, 0x6d9282e698e0aa9039eeb2140ed253cc, 0x2c0469f6a5ab249c9f5a83d78446466d, 0x8f94abe0f41a0f37c9a8ce3093420edd, 0x5cada5f31f083ecb0d73598c9ffa00d1, 0x6c83397784496acbb8baaf16ef1a48be, 0x1a86633a4591bc2904fef9e787f605fa, 0x575ca3ca146d489bfe332ab6990bdcfe, 0x5d784bce637f20b720a26752a3c0825a, 0x4c37b6124c24ae2b764a70d8d0dab1ec, 0x067b2a1387ae025cd995d472c819c4c8, 0x72ae1a8c96603f6208b1c40c8658ca0b, 0x3760cc34abbd4c8cd3c7f6748c6ddc8b, 0xe4646d1750def726e0dfbd7b323c2b4d, 0x477d8e61ce4c2446a649c69260e65273, 0x124879936cb5aeddd65577591412fb1d, 0x4b11698b31cb61de5cd25bb51493bb8a, 0xfaf5ac0ef551d5e75e1b7fd9b84ba448, 0x79ee711f8de133182865740e9263d477, 0xe3496f7a62597557188aad8bf0dedfb8, 0x79f66c9dd633724dc44d1fcb9ae5a157, 0x1c633cee8d1daf2596762eb978114de8, 0x88377d95516b59707a4a33ee2e9ccb95, 0x9f76a25492f5cd3175af35797c814426, 0x007dcb5cab2170cf4eba4c9a97971ebd, 0x03b299b6b0ddc915b77ee58c4150abb1, 0x5bee8e1c291b0b56ed746e9a7b880cb4, 0x89f150e166a2f9295d3f56dfded07296, 0x4301f7ea74cfb5a404e81b818329e160, 0x68d949593bf7308904bc7227836edc9b, 0x9d2161879526db081bd8a1c9efdb4a2b, 0xb6de5abccb007e8fca083f24e29b2c91, 0x4810baaa2bf8dc23a17b0e3ce92736e7, 0xfee7faf291d2ef539af408b9afe2dfac, 0x176e49d9c24624a172face86de86317e, 0x92862dea9f4b90267f66c9968b9c6313, 0x8a708020e7ef3da40d5e4921998dd72e, 0xbeb56c2650b491efd380fe2f1f24cf59, 0x6933566b78d329a9cfe13676c7d0b17a, 0xb226d03c1a24df2f7448eeeed993da85, 0x33e7beac53eb3baa329a6d9f93f07336, 0x393044df5ac57e0c2c2f77a03c3f4962, 0x2d7d0f9895fe8a87cee14614a1ce3941, 0xb3969f72feb880c2dd3cca83edf865e1, 0x1fbd5f4de46a6ef4bd4247e1f11c15e7, 0xd50b59ce736b022c15e1a8da2c2219b1, 0xb1f9a3a87596309352361ab151c2c05d, 0x69796e6ac4b0294c59711f8852b3f162, 0x3dce1d03f3ae1ecb047c4694ab092610, 0x594ae45653ed53f2197077cf9821edb7, 0x47cd782609abba9606375d34cb928625, 0x004f20a18a24f7ab5f2f00c9d4e8f80f, 0xc9dbddfbcc48fdf060acba9c812e2e78, 0x9d8ed2c087de71ed618319d7bcabf320, 0x7d0855188ba1e1509a7a82d0853e5da6, 0x3503f812b89a5b95af9a5c49ce27cd39, 0x72c6357daee430a087ea2c9497d31462, 0x615c3ec740d05437ac115d2a98363168, 0xb7958e1f28ce840e70a968817ea62497, 0xcdeceee77d53a1e047e5c2d8b5a012c0, 0xa5c1074b5a7bc624b06eb5efda918f2f, 0x09c5d6b960ded5a0ef01e109378716b0, 0xe724289c3ffb26a41f1ed782abcef537, 0xdcf81731836c6d96e66d320a1e63b2bf, 0x6ef4dba7fe4fe784b1ed7630c0e7617f, 0xeb9bd8894114fba82bb1d1c89b251f53, 0x3e83d2b41c6022148c63934d229b3621, 0x1e25f7eba32df9bfb24834c509d537bd, 0x8050ae348fbb205726633040c2527ef6, 0xd5882dadc7e42d67e81c4c62519aefb0, 0xa114a20d678ca4fdf0984642fd46e27b, 0x5d1518db22bede27d7475ca40fb95738, 0x326dc5344746e00d2c2d2ae992337ebe, 0xf1f87cd0c3fc1ee31506bd501646d006, 0xa55b11ec8c3272a4f81621bc0b01add5, 0x54d4f7b296ae60c4f15a7236ca49f22b, 0xd23c4aa7093738b51b7a68a0a3fc67aa, 0xdf01f25b0894c3a9bcef4d970e768f95, 0x752057976a3571615d272e19a859fe16, 0x22e79b30f2cd5160e92ed530505645ed, 0x1becebae9724b32d0db81d03ff33da24, 0xce73c335a4efd58c5d0c40c51642dc75, 0x84da2cc236b52bd72787e50edbc9b112, 0x6f274899c6cefba7a5613b4c58faa833, 0x6d7ce2fb0e5cbed31a6b445798c40d6b, 0x6a41b02ab541381d402b846ef7b0e571, 0xdbb323a5322e7c4ce9fea7a4ac5f9ad9, 0xc3961dceaaec587bd5d94ad383a7a2ba, 0x052bee8860cde6f4e724339cca84c484, 0xd6703da7e0d48932407c7ff6a71443c8, 0xf248d03745e9ec4da73d0764c77a226e, 0x49a0852bf4852e0f9c2a5fe5fe7d6641, 0x689178d6137f568dac9f9483abe05023, 0xaf5c896b72db39a596241b27a023dc79, 0x568954a8524d00639d2f8cd163ece427, 0x09b8523fff580934d8576b5ab601a801, 0x4e291c48d3b44e85f6d7d0e7143261be, 0xc89f73b066961dafce3ea5d853a19e62, 0x4f06446b7cd94088d2c174e0c65ace4c, 0x2c3eadb3f0f2de2dd81916a775393213, 0x19ffdb9bf5bb43c4edb17f770afbf60f, 0xdfdf6c597bf92cd8e2b6ae40c67ce578, 0x3a935a0a5ea47e1732fc709b50a2cf71, 0xa374dd88b5e16fb9c696ae1bc6023bdf, 0x7ff39d2010db91f8bbe5fc7360a81c04, 0x757f1cde20bdbeef8113e880eeef710b, 0x3ea232c37ac080f8400f55d9dd3db964, 0xed0615053ef5a1d4e1c3c1087802734e, 0x17a5b18158fc55232b6e758af99d5d30, 0x552bb5754abbb4a7234cc20d33e3f0cb, 0x710aa3cbf477921d48ae540e344d0826, 0xefd221789e4010d957b6705be2013273, 0xe6a70b3255f3776570a194f426a1492a, 0x224766fc07d0ac917d1337dea0d2d1f9, 0x776828780bbf74a2ab330490000c25a5, 0xc2147e59985e1e0150ab85367487ab56, 0xdd1f2794a4d4d1432fcdae0f2efd0453, 0x7f5ee541488129f3566ec5bc78a6af93, 0xfbe326ca123097869ab8f626a156ea83, 0x95146d8972af4c743aad258d1ff28562, 0x0260f69ceefd2b20aa0ad6a186c73572, 0x484d3e3920922b33fb55f1ba13374dc5, 0xf2faefbe1ca5f1beb3cb2a391ef55cd8, 0xfc16b66c895b41c4dbe725923288ad18, 0x7b63b99079f3cb20c2312dccfff5220e, 0xfe18ee87dd2a8cc061f37e5977dfafbc, 0x3453974701755cf8ead4cd614211f5d1, 0xb051fb550ff77f882fb1ceaf3d62b90e, 0x09a3a03715072e8dec06736b4e1188da, 0x385c50218d2dd96f0fa04f3759583761, 0x8b1200eb0297594c7599d5e0873bc3f7, 0xe74457aab8ec03353641a681efd15019, 0x5587e870324e3bc16bf0a23172b15ab3, 0x663baf3790c40eba503da6aa8e198164, 0x4b669ffe9aaa3db5eebc9f961f9bc908, 0xeaf5a1901f9c7aacef52325fd4873612, 0x81bef05ef5447090854572b22b53b994, 0x417cddb14496590301d8e165d57ea427, 0x46dc26522bed4d1c4f5f32094cd6a81b, 0xf6242d0e1593d304290279958a8300d1, 0x3c2d6a0c078a8b28278ce84b18227d48, 0xb9afdfa657a2521d14189d605fedf23a, 0xaaab35b4bab6bc7bb9c10dcb7e91da56, 0x9a028613ddcfc61444082ca33d2768f0, 0x9ef4170eb38593d513af4b9e2ac78f2b, 0x8c6b7ec22926580f74cae6d699372375, 0x4f460562afc13f4557d97d562106b8b1, 0x94cfb86ff625ca8fb1938c0cb0cbbb49, 0x698c3eb156c259a76f0dd94dceb3bd90, 0xcb1fd841d78acabc42e1260b91947293, 0xc3db34d3ec0d5fa058548b5d46e936e7, 0x31f95b32d67c4def93a9d5a2dc84693b, 0x5ae6a637f882709b89b3f7957efe6d6e, 0x5216cde40811875b04e7baa6b2e3fbcd, 0xc5f7f3fa2a94c8dc5972719274c95508, 0x2ffb0f3f9872a9c065c69b99b2d96eb9, 0xb553edb34add19a0aa1b50ff5f972607, 0x8e68e5c6041accb5186246616843ea41, 0x809749669a8704b5c25daca903d72fc3, 0x957778179ddbf70d331e0c595b2d1a3a, 0x08a2305c12fc5fc64b7536952762f5ed, 0x67bb231fed2079de9a70a63a94a755fc, 0x578812958d9b7480ea3783b96e3fc159, 0xfbb1612f4bd2d090eab40d7549f69fd4, 0xe6e330e0a41d73f80652e286b2df190a, 0xb168e7c02ebc22a55f6326285637ad47, 0x28982f9eec0842edba2bd02ad24f9187, 0x8a9c6ccc0d65450e4cbd38ef107a7a4e, 0x79ae37a8b08cf2b7d4d14364aaa89d42, 0xa2561f71a8066b5db2345bf73745b7c1, 0xe0b98da1efd2ecf5b2d7a556a2b59c2e, 0x152d97c817f51e38852b19316b2425a9, 0x6f30d9c91308da7993d4dacfa2a99e9e, 0x743087b52d2f8b24e3f305ca40bf1753, 0x47546b4c93a24bc60d0573029dee587b, 0x5e50e7bdcd8be40596238886d09140a3, 0xec4fc5b635035c33a8f9c6ac5aa91740, 0xe870216c8c5e60366d9586cadacfad7a, 0x75224953f5c18e99ddfbe7b72c3242f2, 0x17f3c6d3f25494597168d1b8d4acd0da, 0x9e3a26b0202150248f454e0dddaafdcb, 0x8849ac05f9760502c0c305bbc0930fc9, 0x11fbdd05ec69f85ffc77a96ac770e5cb, 0xb93d9455974a5f02f1eb33987f29549e, 0xcd7fbd00e17654861c42692cc3fd2dc8, 0x7e736e7596e71c403eb719d1bd1c8156, 0xb6644a59511d9e1ac004e94841283951, 0xa133b7f10a68868a7c2ab3c913f5ba5d, 0xb01b3ab20f81f6b9c9a18209603c99f2, 0x93d2c5ad46e54b1dd7da856a61146e5c, 0xea0096f8966488cf564453f29663f53f, 0x96ed65508aee0e4c6fef043b915f0b13, 0x9094f47273e1391f0b7411b086b1b0f5, 0x299e13bd5ac9be51c2b175b65ad080ec, 0x7feccfc3cfdb89ecd0dee41a1767b2b4, 0xaa14bd3378665df902255d4e7d94b9d9, 0x82ef091a72e9d4fbe733d0806546e97e, 0x5c0e32fab61c330a27588b53971fa628, 0x4f9a5963bd6a1908b5fd5a75aef35224, 0x7c618ec80bc694dc3eb882491c086e0e, 0x44673413960cbf6f6dd9a37c7074aad8, 0xa077efcd0f5962b897050fcf26372f45, 0x3d3bfb3b32a3909a379edeeb22bbb106, 0xe5683a04b445aa05d83939dd850cb683, 0xdb635b6fc2ad4d97b8ebe1f29ca31a38, 0xe3719bf400ba342961e8de5ef6c08013, 0x5cd76c4c414cacefc07ac391f7e2ff55, 0x532c05fb8c0be9a0cae5b64c0b35b25a, 0x128841fbfe4f18fb0a1c8bbcfe812231, 0xd0604bab87dbe9bbf28efb0b90071149, 0xef84aa813f404761f59461a20588206e, 0xaaeb62ad67ed62c59e9f4afffe1a6a9c, 0x6734c16901b0f6d622450719bbb153ef, 0x7d9ace1df72267cba277019fc25e8719, 0x20e38ab642b26d8d233d66496b608d59, 0x8d9d74665a2cad5a56f755f6cd659195, 0xed7584652b24bf6a11da5347fe5c8ec5, 0xc689f0fce8df7ba60fba7447f0691e98, 0x60c78f530caed8c381a85ab62bed5ab0, 0x8ad9db3631ff370abc3ab5050c3b446f, 0x1db581032be71342b230f47ad665e528, 0x92dcac2113dc4f5a6dcafd755aff4f28, 0xf3e7a02346c514f2ea4cb9e5320c616b, 0x53bf94ec3444d4fb9307a231ed08118f, 0x9238df82bc422fed4dcaec2ce22cabd0, 0x0179f30d540cffc7b8a52825da3963df, 0x4a7fc9c4a30c814e4e8163cdbe3e1f1c, 0xdef688a43c73ba2e319da4d2c44761be, 0x492dc4fafb4e2814c31f6caf96dddfd3, 0xc5d8496ab0c9affd57392408b4c1ae86, 0xa8ebd79595bd529ef46e21e7271edee8, 0x2f41917c3b1834f96bbf5a56b3fff25d, 0xc1da5efe0ae8cc14c346894fcd2f489b, 0x87857eb8ab9e218b6b5e6ce4c6ec8998, 0xe1bcd41dc5a5301181c04994c11a0ed5, 0xe2048ce628669933a10ab54b289880dc, 0xa720dd2c261813a6a85d56d38136cd8c, 0x0a0aa64fce5938f85caa6e925298c5dd, 0x6c8d15b228e11fe1e6f8f0f55a906f96, 0xbe0c1766a752251989818198c802cc39, 0x3c11ae2050c64f398721cb03b46e1de1, 0x84ac4966c3e3047a19e1e5da85227615, 0x3f53cb7a771246b6d1ecdbeffa82a7ac, 0x4c546225ad02c22ce71393e28e31899a, 0xa3f4e823888a34f6957eeb238532ac14, 0x8eef0da7474d6f3f8b87ea8d9fc39daf, 0x42a42e643777a75750dc9c27cf62e9bf, 0x81db7c33d793ddf1f6e03300a1878b61, 0x111c5d1459d813f4417583e91316fb80, 0x087345b75096c6dca3fb03b1ae074524, 0x01ac4f71b0135247c4e22f5f07a7a5bf, 0x07d661b603bbfd8891c5680558c15740, 0x62fda8732d1b5e2fca2756391a944890, 0x9c1e993c1de7ed8ad521c98deaf291c0, 0x05b1882578ba1cd61dcbd1156c379f12, 0x270152c3989635eec77d36f96a20369b, 0x1ce82140ccbc04c53a7f788865a90612, 0xd8a526bdc5da2b490be839b98ed05b90, 0x5305f0eeaddd765c72a25d0c8e38f50a, 0x329c8c4f615afd2caba6de354f52ee45, 0xc90268f226df7e2c6237525fb13f7fa5, 0xcb2c0b3823c3bc634c289cec8a6595dd, 0x397510bb499893bb560e30632554eb82, 0x77be8468ced410c556e1b092b76aa1a8, 0xfea8cd161e2fd73d732fab84c97611ef, 0xb53ed820d718f42506df0a6d1a435005, 0x9bdc8726f6ccf7004b6db9c816fe41cf, 0x5534141bc5877839b8e9b75ab12266e3, 0xc608cf667c3217aec9123a26be8243b1, 0x9181410a650d27f5e531c7433bba727a, 0x35f8951fcc213ab1afafe19aeb5f216a, 0xd3c3a0dd7fe1e0f1fa7801a18cf71b49, 0xf6edbfd80bc27ce37b7571e6382f1fa7, 0xffab4ad05540aa08f8918e37e1491799, 0x341f2bacf48d91f74cb1815b38e50a28, 0xa8c799f603c157c0dbac9d34dc1dc9cd, 0x27a7cd6c67ead0923dcbbfe12b7b7c7a, 0xeb40dd362047556983fd9850adaa8292, 0xdca89283addb70a7e7c0bd35a619f097, 0xab778929273b6412e9f897c27f150c15, 0xb04a1ca62695b03a4d804f563cab271f, 0x0ccf8dd0de9c924c13b8af405ca3ad4f, 0x30b31819e945af5dc0b1e5e360dbe56b, 0x080e8e30cb5cca768c97bf09f347faf8, 0x9cac85109bab5bf9cd5a11a5c9cd8eb3, 0xb42bfe8aeb365cc4a8847d641fc52420, 0xe42723fce7959f2b4fc71721fe454b31, 0x255feb846be3520651ba262a553d221b, 0x8e579841ae221e622f5a739d78d88aec]
    test_buf = finalizehash2b(test_key, test_buf)
    print("= finalize2b complete - output = ")
    print(" expected: 73729aa8e3385c68ac707950256ff4d5f0ee4c40a669ef249ed05832976a74bb")
    print("hashbytes: ", ps(test_buf), "\n")

    # print input
    print("= input bytes =")
    print(ps(m) + "\n")

    # call Haraka-512/256
    digest = haraka512256(m)

    # print digest
    print("= haraka-512/256 output bytes =")
    print(ps(digest) + "\n")

    # call Haraka-256/256
    digest = haraka256256(m)

    # print digest
    print("= haraka-256/256 output bytes =")
    print(ps(digest) + "\n")


if __name__ == '__main__':
    main()
