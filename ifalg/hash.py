from ifalg.linux import IfAlg, ALG_TYPE_HASH, STRATEGY_HEURISTIC
from ifalg.proc_crypto import getAlgMeta
from ifalg import utils

class Hash(IfAlg):
    """Kernel Hash Algorithm"""
    def __init__(self, algName, digestsize=None, key=None, strategy=STRATEGY_HEURISTIC):
        """Initializes a kernel hash algorithm.

        Algorithm names and constrains can be seen in ``/proc/crypto``.

        Args:
          algName (str or bytes): Algorithm name, ie: sha1.
          digestsize (int): Algorithm digest size, if None the value will be queried to ``/proc/crypto``
          key (str or bytes, optional): The algorithm key if required, the default is None.
        """
        super(Hash, self).__init__(ALG_TYPE_HASH, algName, key=key, strategy=strategy)
        self._connect()
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
            if data == b'':
                #empty string must be send
                self._send(data)
            else:
                self.sendData(data)
        return self._read(self.digestsize)

    def hexdigest(self, data=None):
        """Similar to digest but returns hash result as hex string"""
        response = self.digest(data)
        return utils.bytesToHex(response)
        
    def update(self, data):
        """Sends data to the algorithm
        
        Params:
          data (bytes): Data to process
        """
        self._send(data, more = True)

    
    
