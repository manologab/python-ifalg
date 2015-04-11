from ifalg.linux import IfAlg, ALG_TYPE_HASH
from ifalg.proc_crypto import getAlgMeta
import binascii

class Hash(IfAlg):
    """Kernel Hash Algorithm"""
    def __init__(self, algName, digestsize=None, key=None,):
        """Initializes a kernel hash algorithm.

        Algorithm names and constrains can be seen in ``/proc/crypto``.

        Args:
          algName (str or bytes): Algorithm name, ie: sha1.
          digestsize (int): Algorithm digest size, if None the value will be queried to ``/proc/crypto``
          key (str or bytes, optional): The algorithm key if required, the default is None.
        """
        super(Hash, self).__init__(ALG_TYPE_HASH, algName, key=key)
        self.connect()
        if digestsize is None:
            self.loadMetadata()
            self.digestsize = self.meta.digestsize
        else:
            self.digestsize = digestsize
        if key is not None:
            self.sendKey()

    def digest(self, data=None):
        """Get hash digest as bytes

        Params:
          data(bytes, optional): data to process, it can be None if update was previously called
            default is None
        Returns:
          hash result as bytes
        """
        
        if data is not None:
            self.send(data)
        return self.read(self.digestsize)

    def hexdigest(self, data=None):
        """Similar to digest but returns hash result as hex string"""
        reponse = self.digest(data)
        return binascii.hexlify(reponse).decode()
        
    def update(self, data):
        """Sends data to the algorithm
        
        Params:
          data (bytes): Data to process
        """
        self.send(data, more = True)

    
    
