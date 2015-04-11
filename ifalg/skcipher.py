# -*- coding: utf-8 -*-
from ifalg.linux import IfAlg, ALG_TYPE_SKCIPHER

class SKCipher(IfAlg):
    """Kernel Symetric Key Cipher Algorithm"""

    def __init__(self, cipherName, key, iv=None):
        """Initializes the symentric key algorithm

        Algorithm names and constrains can be seen in ``/proc/crypto``

        Args:
          cipherName (str): Algorith name, ie: ``cbc(aes)``
          key (str or bytes): cipher key, must comply with cipher size constraints
          iv (str or bytes): Initial Vector, must comply with cipher iv size requirement
        """
        super(SKCipher, self).__init__(ALG_TYPE_SKCIPHER, cipherName, key=key, iv=iv)
        self.connect()
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
        sendedLen = self.sendmsg(data, encrypt=encrypt)
        return self.read(sendedLen)
        

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

