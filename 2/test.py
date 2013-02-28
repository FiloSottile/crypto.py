import unittest
import hashlib

try:
    from ssl import RAND_pseudo_bytes, RAND_bytes
except ImportError:
    import os
    RAND_bytes = os.urandom
    RAND_pseudo_bytes = lambda n: (os.urandom(n), True)


class Python2Tests(unittest.TestCase):
    def test_md4(self):
        import md4
        test_vector = {
            '': '31d6cfe0d16ae931b73c59d7e0c089c0',
            'a': 'bde52cb31de33e46245e05fbdbd6fb24',
            'abc': 'a448017aaf21d8525fc10ae87aa6729d',
            'message digest': 'd9130a8164549fe818874806e1c7014b',
            'abcdefghijklmnopqrstuvwxyz': 'd79e1c308aa5bbcdeea8ed63df412da9',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789': '043f8582f241db351ce627e153e7f0e4',
            '12345678901234567890123456789012345678901234567890123456789012345678901234567890': 'e33b4ddc9c38f2199c3e7b164fcc0536' }
        for m, h in test_vector.items():
            self.assertEqual(md4.MD4(m).hexdigest(), h)

    def test_sha1(self):
        import sha1
        stuff = RAND_pseudo_bytes(500)[0]
        for n in range(500):
            self.assertEqual(hashlib.sha1(stuff[:n]).hexdigest(),
                sha1.SHA1(stuff[:n]).hexdigest())

    def test_md5(self):
        import md5
        stuff = RAND_pseudo_bytes(500)[0]
        for n in range(500):
            self.assertEqual(hashlib.md5(stuff[:n]).hexdigest(),
                md5.MD5(stuff[:n]).hexdigest())
