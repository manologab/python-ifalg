 Python ifalg
==============

**ifalg** is a Python 3 library to interface with the Linux kernel crypto API.
This is generally slower than using a library like OpenSSL or PyCrypto,
but it could be useful if you have cryptographic hardware supported by Linux.

Features
========

* For the moment only *skcipher* and *hash* algorithms are supported.
* Algorithm metadata is parsed from */proc/crypto*

Samples
=======

Using a hash algorithm::

  >>> from ifalg import Hash
  >>> hash = Hash('sha1')
  >>> hash.hexdigest(b'hello world')
  '2aae6c35c94fcfb415dbe95f408b9ce91ee846ed'

Using a keyed hash algorithm::

  >>> from ifalg import Hash
  >>> hash = Hash('cmac(des3_ede)', key=bytes.fromhex('8aa83bf8cbda10620bc1bf19fbb6cd58bc313d4a371ca8b5'))
  >>> hash.hexdigest(bytes.fromhex('6bc1bee22e409f96'))
  '8e8f293136283797'

Encryption and Decryption::

  >>> from ifalg import SKCipher
  >>> cipher = SKCipher('cbc(aes)', key=bytes.fromhex('790afba9cfbc095b682666a6999a38ed'), iv=bytes.fromhex('fb1f88c0f23d6aa6dde475c018d7f482'))
  >>> msg = bytes.fromhex('4e0c74c8d67862a9732604f62f4ad316')
  >>> cipherText = cipher.encrypt(msg)
  >>> cipherText
  b'\x7ftT$Z\xf4\xe6|\xd2)cA\xf2\x1d\xcb\xa9'
  >>> plainText = cipher.decrypt(cipherText)
  >>> plainText
  b'N\x0ct\xc8\xd6xb\xa9s&\x04\xf6/J\xd3\x16'
  >>> plainText == msg
  True
