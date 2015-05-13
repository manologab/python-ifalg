import unittest

#from ifalg import SKCipher, IV
from ifalg.linux import IfAlg
from tests import cavs, cavs_mmt
from ifalg import SKCipher, SKCipherStream, Hash, STRATEGY_SENDMSG, STRATEGY_SPLICE, utils, InvalidAlgError
from ifalg.proc_crypto import parseProcCrypto, getAlgMeta
import six
import logging
import os
import subprocess
import re

log = logging.getLogger(__name__)

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

    def testInvalidAlg(self):
        key = os.urandom(16)
        with self.assertRaises(InvalidAlgError):
            SKCipher('NoNameHere', key=key)

        with self.assertRaises(InvalidAlgError):
            Hash('NoNameHere')
        

    def _test_all_ciphers(self, strategy):
        """Test all skcipher's"""
        for (i, vec) in enumerate(cavs.SKCIPHER):
            name = vec['name']
            msg = bytes.fromhex(vec['msg'])
            exp = bytes.fromhex(vec['exp'])
            #log.debug('testing cipher: %s, len(msg)=%d, len(exp):%d', name, len(msg), len(exp))
            cipher = SKCipher(name, key=bytes.fromhex(vec['key']), strategy = strategy)
            if 'iv' in vec:
                cipher.setIV(bytes.fromhex(vec['iv']))
            if vec['enc']:
                result = cipher.encrypt(msg)
            else:
                result = cipher.decrypt(msg)

            self.assertEqual(result, exp,
                             'Fail while testing skcipher #%i %s, len(result):%d'%(i, name, len(result)))
            cipher.close()
    def test_all_ciphers_sendmsg(self):
        return self._test_all_ciphers(STRATEGY_SENDMSG);

    def test_all_ciphers_splice(self):
        return self._test_all_ciphers(STRATEGY_SPLICE);

    def _test_all_hashes(self, strategy):
        """Test all hashes"""
        for (i, vec) in enumerate(cavs.HASH):
            name = vec['name']
            try:
                key = bytes.fromhex(vec['key'])
            except KeyError:
                key = None
            hash = Hash(name, key=key, strategy=strategy)
            msg = bytes.fromhex(vec['msg'])
            result = hash.hexdigest(msg)
            self.assertEqual(result, vec['exp'],
                             'Fail while testing hash #%d %s, vector:%r'%(i, name, vec))

    def test_all_hashes_sendmsg(self):
        return self._test_all_hashes(STRATEGY_SENDMSG)

    def test_all_hashes_splice(self):
        return self._test_all_hashes(STRATEGY_SPLICE)
    

class TestMMT(unittest.TestCase):
    """Multi Message Text testing"""
    def _test_vector(self, piv, vec):
        name = vec['name']
        msg = bytes.fromhex(vec['msg'])
        exp = bytes.fromhex(vec['exp'])
        iv = bytes.fromhex(vec['iv'])
        blocksize = len(iv)
        #log.debug('testing cipher: %s, len(msg)=%d, len(exp):%d', name, len(msg), len(exp))
        cipher = SKCipherStream(name, key=bytes.fromhex(vec['key']), iv = iv, encrypt=vec['enc'])
        result = []
        for i in range(0, len(msg), blocksize):
            ll = cipher.write(msg[i:i+blocksize])
            self.assertEqual(ll, blocksize, 'not all data was written')
            result.append(cipher.read(ll))
        result = utils.bytesToHex(b''.join(result))
        #log.debug('result:%s', result)
        cipher.close()
        self.assertEqual(result, utils.bytesToHex(exp),
                         'Fail while testing skcipher[%d] %s, len(result):%d'%(piv, name, len(result)))

    def test_all_mmt(self):
        for (i, vec) in enumerate(cavs_mmt.SKCIPHER):
            self._test_vector(i, vec)
        


class TestOpenSSLHash(unittest.TestCase):
    """Test hashes with large random data from /dev/urandom and compare the result with openssl"""
    def _test_openssl_hash(self, algName):
        with subprocess.Popen(('openssl', algName), stdin=subprocess.PIPE,
                              stdout = subprocess.PIPE, stderr = subprocess.STDOUT) as proc:
            hash = Hash(algName)
            step = 128*1024 #128K steps
            for i in range(80):#10MB
                data = os.urandom(step)
                proc.stdin.write(data)
                hash.update(data)

            proc.stdin.close()
            out = proc.stdout.read().decode('utf8', errors='ignore')
            mt = re.match('^\(stdin\)= (\w+)$', out)
            if not mt:
                self.fail('openssl output error: %s'%(out,))

            opensslResult = mt.group(1)
            myResult = hash.hexdigest()
            self.assertEqual(myResult, opensslResult)
            hash.close()
            
    def test_openssl_sha1(self):
        return self._test_openssl_hash('sha1')
    def test_openssl_sha224(self):
        return self._test_openssl_hash('sha224')
    def test_openssl_sha256(self):
        return self._test_openssl_hash('sha256')
    def test_openssl_sha384(self):
        return self._test_openssl_hash('sha384')
    def test_openssl_sha512(self):
        return self._test_openssl_hash('sha512')
        
class TestOpenSSLCipher(unittest.TestCase):
    """Test ciphers with large random data from /dev/urandom and compare the result with openssl"""
    def _test_openssl_cipher(self, algName, opensslName, encrypt, keysize, ivsize):
        key = os.urandom(keysize)
        iv = os.urandom(ivsize)
        op = '-e' if encrypt else '-d'
        opensslCmd = "openssl enc -%s %s -K %s -iv %s -nopad | sha1sum -"%(opensslName, op, utils.bytesToHex(key), utils.bytesToHex(iv))
        #log.debug("opensslCmd: %s"%opensslCmd)
        with subprocess.Popen(opensslCmd, shell=True, stdin=subprocess.PIPE,
                              stdout = subprocess.PIPE, stderr = subprocess.STDOUT) as proc, subprocess.Popen(('sha1sum', '-'), stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.STDOUT) as sha1proc:

            cipher = SKCipherStream(algName, key = key, iv = iv, encrypt=encrypt)
            step = 32 * 1024#32KBs steps
            for i in range(64): #2MB Total
                data = os.urandom(step)
                proc.stdin.write(data)
                ll = cipher.write(data)
                self.assertEqual(ll, len(data), 'not all data was writen')
                ct = cipher.read(ll)
                #log.debug('ciphertext: %s', utils.bytesToHex(ct))
                sha1proc.stdin.write(ct)
                
                
            proc.stdin.close()
            sha1proc.stdin.close()
            opensslResult = proc.stdout.read()
            myResult = sha1proc.stdout.read()
            self.assertEqual(myResult, opensslResult)
            cipher.close()

    def test_cipher_aes_256_cbc(self):
        return self._test_openssl_cipher('cbc(aes)', 'aes-256-cbc', True, 32, 16)
        
        
    
if __name__ == '__main__':
    logging.basicConfig(level = logging.DEBUG)
    unittest.main()
