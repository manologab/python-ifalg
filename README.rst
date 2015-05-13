Python ifalg
==============

**ifalg** is a Python 3 library to interface with the Linux kernel crypto API.
This is generally slower than using a library like OpenSSL or PyCrypto,
but it could be useful if you have cryptographic hardware supported by Linux.

Features
========

* For the moment only *skcipher* and *hash* algorithms are supported.
* Algorithm metadata is parsed from */proc/crypto*

Installation
============

*ifalg* should work on any Linux distribution with a modern kernel, in order to use this tool you need to have the folowing options enabled on the kernel:

* CONFIG_CRYPTO_USER_API
* CONFIG_CRYPTO_USER_API_HASH
* CONFIG_CRYPTO_USER_API_SKCIPHER

To install just use pip::

  pip install ifalg

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

Streaming encryption and decryption::

  >>> from ifalg import SKCipherStream
  >>> stream = SKCipherStream('cbc(aes)', key=bytes.fromhex('790afba9cfbc095b682666a6999a38ed'), iv=bytes.fromhex('fb1f88c0f23d6aa6dde475c018d7f482'))
  >>> stream.write(b'0123456789abcdef0123456789abcdef')
  32
  >>> cipherText = stream.read(32)



Author
======

Manolo Ramirez T manologab@gmail.com

Contact
=======

For any thoughts about this software, please contact me at manologab@gmail.com.

If you find a bug or have any idea to improve this tool, please use Github's `issues <https://github.com/manologab/python-ifalg/issues>`.

License
=======

The MIT License (MIT)

Copyright (c) 2015 Manolo Ramirez T.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
