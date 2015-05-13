# -*- coding: utf-8 -*-
from ifalg.linux import IfAlg, ALG_TYPE_SKCIPHER, STRATEGY_HEURISTIC, STRATEGY_SENDMSG, STRATEGY_SPLICE

class SKCipher(IfAlg):
    """Kernel Symetric Key Cipher Algorithm for oneshot operations"""

    def __init__(self, cipherName, key, iv=None, strategy = STRATEGY_HEURISTIC):
        """Initializes the symentric key algorithm

        Algorithm names and constrains can be seen in ``/proc/crypto``

        Args:
          cipherName (str): Algorith name, ie: ``cbc(aes)``
          key (str or bytes): cipher key, must comply with cipher size constraints
          iv (str or bytes): Initial Vector, must comply with cipher iv size requirement
        """
        super(SKCipher, self).__init__(ALG_TYPE_SKCIPHER, cipherName, key=key, iv=iv, strategy = strategy)
        self._connect()
        self.sendKey()

    def crypt(self, data, encrypt=True):
        """Encrypt/Decrypt data

        Args:
          data (str, bytes): Data to encrypt/decrypt
          encrypt(boolean, optional): True to encrypt, default is False

        Returns:
          The encrypted ciphertext as bytes

        Raises:
          IOIfAlgError: If an error was returned by the kernel
          InvalidStateError: If the AF_ALG socket is not connected
        """
        sendedLen = self.sendData(data, encrypt=encrypt)
        return self._read(sendedLen)
        

    def encrypt(self, data):
        """Encrypts data

        It is the same that
        crypt(data, encrypt=True)
        """
        return self.crypt(data, encrypt=True)

    def decrypt(self, data):
        """Decrypts data

        It is the same that
        crypt(data, encrypt=False)
        """
        return self.crypt(data, encrypt=False)

class SKCipherStream(IfAlg):
    """Symetric key cipher algorithm for streaming operations"""

    def __init__(self, cipherName, key, iv=None, encrypt = True):
        """Initializes the symentric key algorithm

        Algorithm names and constrains can be seen in ``/proc/crypto``

        Args:
          cipherName (str): Algorith name, ie: ``cbc(aes)``
          key (bytes): cipher key, must comply with cipher size constraints
          iv (bytes, optional): Initial Vector, must comply with cipher iv size requirement.
          encrypt (bool, optional): True to encrypt, False to decrypt. Default is True
        """
        super(SKCipherStream, self).__init__(ALG_TYPE_SKCIPHER, cipherName, key=key, iv=iv,
                                             strategy = STRATEGY_SENDMSG)
        self._connect()
        self.sendKey()
        self.encrypt = encrypt
        self.initialized = False

    def setEncrypt(self, encrypt):
        """Set operation to encrypt or decrypt

        Args:
          encrypt (boolean): True to encrypt, otherwise decrypt
        """
        if self.initialized:
            raise InvalidStateError('already initialized')

        self.encrypt = encrypt
    
    def write(self, data):
        """Write data to encrypt/decrypt

        Returns:
          The amount of data writed
        """
        if not self.initialized:
            self._sendmsg(data=None, encrypt = self.encrypt, more=True)
            self.initialized = True

        r = self._sendmsg(data, encrypt=None, more=True)
        return r

    def read(self, size):
        """Read encrypted/decrypted data"""
        return self._recvmsg(size)
