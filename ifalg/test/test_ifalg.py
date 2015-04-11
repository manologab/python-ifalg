import unittest

#from ifalg import SKCipher, IV
from ifalg.linux import IfAlg
from ifalg.test import cavs
from ifalg import SKCipher, Hash
from ifalg.proc_crypto import parseProcCrypto, getAlgMeta
import six

class TestUtils(unittest.TestCase):
    def test_parseProcCrypto(self):
        algs = parseProcCrypto()
        for (algName, algMetas) in algs.items():
            self.assertIsInstance(algName, six.string_types)
            lastMeta = None
            for meta in algMetas:
                if lastMeta:
                    self.assertTrue(lastMeta.priority <= meta.priority, 'Algorithm order incorrect')
                    lastMeta = meta

    def test_aes(self):
        aes = getAlgMeta('aes')
        self.assertEqual(aes.blocksize, 16)
        self.assertEqual(aes.minKeysize, 16)
        self.assertEqual(aes.maxKeysize, 32)

    def test_des(self):
        alg = getAlgMeta('des')
        self.assertEqual(alg.blocksize, 8)
        self.assertEqual(alg.minKeysize, 8)
        self.assertEqual(alg.maxKeysize, 8)

    def test_cbc_aes(self):
        alg = getAlgMeta('cbc(aes)')
        self.assertEqual(alg.blocksize, 16)
        self.assertEqual(alg.minKeysize, 16)
        self.assertEqual(alg.maxKeysize, 32)
        self.assertEqual(alg.ivsize, 16)
        
    def test_xts_aes(self):
        alg = getAlgMeta('xts(aes)')
        self.assertEqual(alg.blocksize, 16)
        self.assertEqual(alg.minKeysize, 32)
        self.assertEqual(alg.maxKeysize, 64)
        self.assertEqual(alg.ivsize, 16)

    def test_sha1(self):
        alg = getAlgMeta('sha1')
        self.assertEqual(alg.blocksize, 64)
        self.assertEqual(alg.digestsize, 20)

    def test_des3_ede(self):
        alg = getAlgMeta('cmac(des3_ede)')
        self.assertEqual(alg.blocksize, 8)
        self.assertEqual(alg.digestsize, 8)
        
        

class TestIFALG(unittest.TestCase):

    def test_all_ciphers(self):
        """Test all skcipher's"""
        for (i, vec) in enumerate(cavs.SKCIPHER):
            name = vec['name']
            cipher = SKCipher(name, key=bytes.fromhex(vec['key']))
            if 'iv' in vec:
                cipher.setIV(bytes.fromhex(vec['iv']))
            msg = bytes.fromhex(vec['msg'])
            if vec['enc']:
                result = cipher.encrypt(msg)
            else:
                result = cipher.decrypt(msg)

            exp = bytes.fromhex(vec['exp'])
            self.assertEqual(result, exp,
                             'Fail while testing skcipher #%i %s, vec:%r'%(i, name,vec))
            cipher.close()

    def test_all_hashes(self):
        """Test all hashes"""
        for (i, vec) in enumerate(cavs.HASH):
            name = vec['name']
            try:
                key = bytes.fromhex(vec['key'])
            except KeyError:
                key = None
            hash = Hash(name, key=key)
            msg = bytes.fromhex(vec['msg'])
            result = hash.hexdigest(msg)
            self.assertEqual(result, vec['exp'],
                             'Fail while testing hash #%d %s, vector:%r'%(i, name, vec))
            
    
    
if __name__ == '__main__':
    unittest.main()
