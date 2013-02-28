# MD5 Python 3 implementation
# Copyright (C) 2013  Filippo Valsorda
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Based on a Python license work by Dinu C. Gherman (C) 2001
# http://starship.python.net/crew/gherman/programs/md5py/md5py.py
# implemented using Bruce Schneier's "Applied Cryptography", 2nd ed., 1996

import struct
import binascii

lrot = lambda x, n: (x << n) | (x >> (32 - n))


class MD5():

    A, B, C, D = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
    length = 0
    count = [0, 0]
    input = []

    # Length of the final hash (in bytes).
    HASH_LENGTH = 16
    # Length of a block (the number of bytes hashed in every transform).
    DATA_LENGTH = 64

    # F, G, H and I are basic MD5 functions.
    _F = lambda self, x, y, z: (x & y) | ((~x) & z)
    _G = lambda self, x, y, z: (x & z) | (y & (~z))
    _H = lambda self, x, y, z: x ^ y ^ z
    _I = lambda self, x, y, z: y ^ (x | (~z))

    @staticmethod
    def _XX(func, a, b, c, d, x, s, ac):
        """
        Wrapper for call distribution to functions F, G, H and I.
        This replaces functions FF, GG, HH and II.
        """

        res = (a + func(b, c, d) + x + ac) & 0xffffffff
        res = lrot(res, s) & 0xffffffff
        res = (res + b) & 0xffffffff

        return res

    def __init__(self, message):
        length = struct.pack('<Q', len(message) * 8)
        while len(message) > 64:
            self._handle(message[:64])
            message = message[64:]
        message += b'\x80'
        message += bytes((56 - len(message) % 64) % 64)
        message += length
        while len(message):
            self._handle(message[:64])
            message = message[64:]

    def _handle(self, chunk):
        w = list(struct.unpack('<' + 'I' * 16, chunk))

        a, b, c, d = A, B, C, D = self.A, self.B, self.C, self.D

        # Round 1.

        S11, S12, S13, S14 = 7, 12, 17, 22

        a = self._XX(self._F, a, b, c, d, w[0], S11, 0xD76AA478)   # 1
        d = self._XX(self._F, d, a, b, c, w[1], S12, 0xE8C7B756)   # 2
        c = self._XX(self._F, c, d, a, b, w[2], S13, 0x242070DB)   # 3
        b = self._XX(self._F, b, c, d, a, w[3], S14, 0xC1BDCEEE)   # 4
        a = self._XX(self._F, a, b, c, d, w[4], S11, 0xF57C0FAF)   # 5
        d = self._XX(self._F, d, a, b, c, w[5], S12, 0x4787C62A)   # 6
        c = self._XX(self._F, c, d, a, b, w[6], S13, 0xA8304613)   # 7
        b = self._XX(self._F, b, c, d, a, w[7], S14, 0xFD469501)   # 8
        a = self._XX(self._F, a, b, c, d, w[8], S11, 0x698098D8)   # 9
        d = self._XX(self._F, d, a, b, c, w[9], S12, 0x8B44F7AF)   # 10
        c = self._XX(self._F, c, d, a, b, w[10], S13, 0xFFFF5BB1)  # 11
        b = self._XX(self._F, b, c, d, a, w[11], S14, 0x895CD7BE)  # 12
        a = self._XX(self._F, a, b, c, d, w[12], S11, 0x6B901122)  # 13
        d = self._XX(self._F, d, a, b, c, w[13], S12, 0xFD987193)  # 14
        c = self._XX(self._F, c, d, a, b, w[14], S13, 0xA679438E)  # 15
        b = self._XX(self._F, b, c, d, a, w[15], S14, 0x49B40821)  # 16

        # Round 2.

        S21, S22, S23, S24 = 5, 9, 14, 20

        a = self._XX(self._G, a, b, c, d, w[1], S21, 0xF61E2562)   # 17
        d = self._XX(self._G, d, a, b, c, w[6], S22, 0xC040B340)   # 18
        c = self._XX(self._G, c, d, a, b, w[11], S23, 0x265E5A51)  # 19
        b = self._XX(self._G, b, c, d, a, w[0], S24, 0xE9B6C7AA)   # 20
        a = self._XX(self._G, a, b, c, d, w[5], S21, 0xD62F105D)   # 21
        d = self._XX(self._G, d, a, b, c, w[10], S22, 0x02441453)  # 22
        c = self._XX(self._G, c, d, a, b, w[15], S23, 0xD8A1E681)  # 23
        b = self._XX(self._G, b, c, d, a, w[4], S24, 0xE7D3FBC8)   # 24
        a = self._XX(self._G, a, b, c, d, w[9], S21, 0x21E1CDE6)   # 25
        d = self._XX(self._G, d, a, b, c, w[14], S22, 0xC33707D6)  # 26
        c = self._XX(self._G, c, d, a, b, w[3], S23, 0xF4D50D87)   # 27
        b = self._XX(self._G, b, c, d, a, w[8], S24, 0x455A14ED)   # 28
        a = self._XX(self._G, a, b, c, d, w[13], S21, 0xA9E3E905)  # 29
        d = self._XX(self._G, d, a, b, c, w[2], S22, 0xFCEFA3F8)   # 30
        c = self._XX(self._G, c, d, a, b, w[7], S23, 0x676F02D9)   # 31
        b = self._XX(self._G, b, c, d, a, w[12], S24, 0x8D2A4C8A)  # 32

        # Round 3.

        S31, S32, S33, S34 = 4, 11, 16, 23

        a = self._XX(self._H, a, b, c, d, w[5], S31, 0xFFFA3942)   # 33
        d = self._XX(self._H, d, a, b, c, w[8], S32, 0x8771F681)   # 34
        c = self._XX(self._H, c, d, a, b, w[11], S33, 0x6D9D6122)  # 35
        b = self._XX(self._H, b, c, d, a, w[14], S34, 0xFDE5380C)  # 36
        a = self._XX(self._H, a, b, c, d, w[1], S31, 0xA4BEEA44)   # 37
        d = self._XX(self._H, d, a, b, c, w[4], S32, 0x4BDECFA9)   # 38
        c = self._XX(self._H, c, d, a, b, w[7], S33, 0xF6BB4B60)   # 39
        b = self._XX(self._H, b, c, d, a, w[10], S34, 0xBEBFBC70)  # 40
        a = self._XX(self._H, a, b, c, d, w[13], S31, 0x289B7EC6)  # 41
        d = self._XX(self._H, d, a, b, c, w[0], S32, 0xEAA127FA)   # 42
        c = self._XX(self._H, c, d, a, b, w[3], S33, 0xD4EF3085)   # 43
        b = self._XX(self._H, b, c, d, a, w[6], S34, 0x04881D05)   # 44
        a = self._XX(self._H, a, b, c, d, w[9], S31, 0xD9D4D039)   # 45
        d = self._XX(self._H, d, a, b, c, w[12], S32, 0xE6DB99E5)  # 46
        c = self._XX(self._H, c, d, a, b, w[15], S33, 0x1FA27CF8)  # 47
        b = self._XX(self._H, b, c, d, a, w[2], S34, 0xC4AC5665)   # 48

        # Round 4.

        S41, S42, S43, S44 = 6, 10, 15, 21

        a = self._XX(self._I, a, b, c, d, w[0], S41, 0xF4292244)   # 49
        d = self._XX(self._I, d, a, b, c, w[7], S42, 0x432AFF97)   # 50
        c = self._XX(self._I, c, d, a, b, w[14], S43, 0xAB9423A7)  # 51
        b = self._XX(self._I, b, c, d, a, w[5], S44, 0xFC93A039)   # 52
        a = self._XX(self._I, a, b, c, d, w[12], S41, 0x655B59C3)  # 53
        d = self._XX(self._I, d, a, b, c, w[3], S42, 0x8F0CCC92)   # 54
        c = self._XX(self._I, c, d, a, b, w[10], S43, 0xFFEFF47D)  # 55
        b = self._XX(self._I, b, c, d, a, w[1], S44, 0x85845DD1)   # 56
        a = self._XX(self._I, a, b, c, d, w[8], S41, 0x6FA87E4F)   # 57
        d = self._XX(self._I, d, a, b, c, w[15], S42, 0xFE2CE6E0)  # 58
        c = self._XX(self._I, c, d, a, b, w[6], S43, 0xA3014314)   # 59
        b = self._XX(self._I, b, c, d, a, w[13], S44, 0x4E0811A1)  # 60
        a = self._XX(self._I, a, b, c, d, w[4], S41, 0xF7537E82)   # 61
        d = self._XX(self._I, d, a, b, c, w[11], S42, 0xBD3AF235)  # 62
        c = self._XX(self._I, c, d, a, b, w[2], S43, 0x2AD7D2BB)   # 63
        b = self._XX(self._I, b, c, d, a, w[9], S44, 0xEB86D391)   # 64

        A = (A + a) & 0xffffffff
        B = (B + b) & 0xffffffff
        C = (C + c) & 0xffffffff
        D = (D + d) & 0xffffffff

        self.A, self.B, self.C, self.D = A, B, C, D

    def digest(self):
        return struct.pack('<IIII', self.A, self.B, self.C, self.D)

    def hexdigest(self):
        return binascii.hexlify(self.digest()).decode()
