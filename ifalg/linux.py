"""Low level communications with linux AF_ALG sockets"""

from cffi import FFI
from ifalg import utils
from ifalg.proc_crypto import getAlgMeta
import os


_FFI = FFI()
_FFI.cdef("""

#define AF_ALG ...
#define SOL_ALG ...
#define SOCK_SEQPACKET ...
#define SOCK_SEQPACKET ...
#define ALG_SET_KEY ...
#define ALG_SET_IV ...
#define ALG_SET_OP ...
#define ALG_OP_ENCRYPT ...
#define ALG_OP_DECRYPT ...
#define MSG_MORE ...

typedef unsigned short int sa_family_t;
typedef unsigned int socklen_t;

struct sockaddr {
    sa_family_t sa_family;
    char        sa_data[14];
};

struct sockaddr_alg {
    uint16_t	salg_family;
    unsigned char salg_type[14];
    uint32_t	salg_feat;
    uint32_t	salg_mask;
    unsigned char salg_name[64];
};

int socket(int domain, int type, int protocol);
int bind(int sockfd, struct sockaddr *addr, socklen_t addrlen);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int close(int fd);
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t read(int fd, void *buf, size_t count);

struct iovec {                    /* Scatter/gather array items */
    void  *iov_base;              /* Starting address */
    size_t iov_len;               /* Number of bytes to transfer */
};

struct msghdr {
    void         *msg_name;       /* optional address */
    socklen_t     msg_namelen;    /* size of address */
    struct iovec *msg_iov;        /* scatter/gather array */
    size_t        msg_iovlen;     /* # elements in msg_iov */
    void         *msg_control;    /* ancillary data, see below */
    size_t        msg_controllen; /* ancillary data buffer len */
    int           msg_flags;      /* flags on received message */
};


struct cmsghdr {
    size_t cmsg_len;    /* data byte count, including header */
    int       cmsg_level;  /* originating protocol */
    int       cmsg_type;   /* protocol-specific type */
    ...;
};

struct cmsghdr *CMSG_FIRSTHDR(struct msghdr *msgh);
struct cmsghdr *CMSG_NXTHDR(struct msghdr *msgh, struct cmsghdr *cmsg);
size_t CMSG_ALIGN(size_t length);
size_t CMSG_SPACE(size_t length);
size_t CMSG_LEN(size_t length);
unsigned char *CMSG_DATA(struct cmsghdr *cmsg);

struct af_alg_iv {
  uint32_t	ivlen;
  uint8_t	iv[0];
};

""")

_C = _FFI.verify("""
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

""", libraries=[])

#Algorithm types
#aead and rng are not supported yet, ther require kernel >= 3.2
ALG_TYPE_SKCIPHER = 'skcipher'
ALG_TYPE_HASH = 'hash'
ALG_TYPES = [ALG_TYPE_SKCIPHER, ALG_TYPE_HASH]

class IfAlgError(Exception):
    """Base error class"""
    pass

class InvalidStateError(IfAlgError):
    """Raised when the agorithm is not ready for an operation"""
    pass

class IOIfAlgError(IfAlgError):
    """Error returned by the kernel crypto API"""
    def __init__(self, msg, errno):
        self.msg = msg
        self.errno = errno

    def __str__(self):
        return '%s: [%d]%s'%(self.msg, self.errno, os.strerror(self.errno))

class IfAlg:
    """Low level interface to if_alg.h
    
    Best use ifalg.SKCipher or ifalg.Hash
    """
    def __init__(self, algType, algName, key=None, iv=None):
        """Initializes a crypto API algorithm

        Params:
          algType (str): Algorithm type, valid values are: ALG_TYPE_SKCIPHER and ALG_TYPE_HASH
          algName (str): Algorithm name
          key (bytes, optional): Algorithm key if necesary, default is None
          iv  (bytes, optional): Algorithm Initial vector, default is None

        Raises:
          ValueError: For invalid parameters
        
        """
        if algType not in ALG_TYPES:
            raise ValueError('algType not supported: %s'%(algType,))
        if algType is None:
            raise ValueError('algType is required')
        if algName is None:
            raise ValueError('algName is required')

        self.algTypeBytes = utils.strToBytes(algType)
        if len(self.algTypeBytes)>=14:
            raise ValueError('len(algType) must be < 14')
        self.algType = algType
            
        self.algNameBytes = utils.strToBytes(algName)
        if len(self.algNameBytes) >=64:
            raise ValueError('len(algName) must be < 64')
        self.algName = algName

        self.setKey(key)
        self.setIV(iv)

        #the socket
        self.sockfd = None
        self.fd = None
        
        #algorithm metadata
        self.meta = None

    def connect(self):
        """Establish connection with the AF_ALG socket

        Raises:
          InvalidStateError: if the socket is already connected
          IOIfAlgError: error returned by the kernel
        """
        if self.sockfd is not None:
            raise InvalidStateError('socket already connected')

        try:
            self.sockfd = _C.socket(_C.AF_ALG, _C.SOCK_SEQPACKET, 0)
            if self.sockfd == -1:
                raise IOIfAlgError('Error opening socket', _FFI.errno)

            alg = _FFI.new('struct sockaddr_alg *')
            alg.salg_family = _C.AF_ALG
            alg.salg_type = self.algTypeBytes
            alg.salg_name = self.algNameBytes

            r = _C.bind(self.sockfd, _FFI.cast('struct sockaddr *', alg), _FFI.sizeof("struct sockaddr_alg"))
            if r == -1:
                raise IOIfAlgError('Error binding socket', _FFI.errno)

            self.fd = _C.accept(self.sockfd, _FFI.NULL, _FFI.NULL)
            if self.fd == -1:
                raise IOIfAlgError('Error during socket accept', _FFI.errno)
        finally:
            try:
                if self.fd > 0:
                    _C.close(fd)
                if self.sockfd > 0:
                    _C.close(sockfd)
            except:
                pass

    def loadMetadata(self):
        """Loads algorithm metadata from ``/proc/crypto``

        Returns:
          A ifalg.AlgMeta instance
        """
        self.meta = getAlgMeta(self.algName)
        return self.meta


    def close(self):
        """Close the socket connections"""
        if self.fd > 0:
            _C.close(self.fd)
        if self.sockfd > 0:
            _C.close(self.sockfd)


    def setKey(self, key):
        """Sets the algorithm key"""
        self.key = None if key is None else utils.strToBytes(key)

    def setIV(self, iv):
        """Sets the Initial Vector"""
        self.iv = None if iv is None else utils.strToBytes(iv)
        
        
    def _checkConnected(self):
        """Check that the socket connection is established,
        Raises:
          InvalidStateError: if not connected
        """
        if self.sockfd <=0 or self.fd <=0:
            raise InvalidStateError('Not Connected')

    def sendKey(self):
        """Sends the algorithm key to the socket"""
        self._checkConnected()

        r = _C.setsockopt(self.sockfd, _C.SOL_ALG, _C.ALG_SET_KEY, self.key, len(self.key))
        if r == -1:
            raise IOIfAlgError('Error setting key', _FFI.errno)
        

    def sendmsg(self, data=None, encrypt=True, more=False):
        """Low level data sending

        data -- raw data for the algoritm (default: None)
        encrypt -- True to encrypt, False to decrypt. if None the operation type and the IV are not send (default: True)
        more -- True to include the MSG_MORE flag (default: False)
        """
        self._checkConnected()

        #build data iovec
        if data is None:
            iov = None
        else:
            data = utils.strToBytes(data)
            iov_base = _FFI.new('uint8_t[]', data)
            iov = _FFI.new('struct iovec *')
            iov.iov_base = _FFI.cast('void *', _FFI.cast('uintptr_t', iov_base))
            iov.iov_len = _FFI.sizeof(iov_base) -1 #ffi includes a '\0' char at the end of the string
            
        if encrypt is None:
            oper = None
        else:
            oper = _C.ALG_OP_ENCRYPT if encrypt else _C.ALG_OP_DECRYPT

        if oper is None and iov is None:
            raise ValueError('no data or meta data specified')

        if self.iv is None:
            ivLength = 0
            ivMsgSize = 0
        else:
            ivLength = len(self.iv)
            ivMsgSize = _C.CMSG_SPACE(_FFI.sizeof('struct af_alg_iv') + ivLength)

        if oper is None:
            #no metadata to send
            bufSize = 0
            buf = _FFI.NULL
            operSize = 0
        else:
            #allocate buffer to specify operation (encrypt/decrypt) and IV
            operSize = _FFI.sizeof('uint32_t')
            bufSize = _C.CMSG_SPACE(operSize) + ivMsgSize
            buf = _FFI.new('char []', bufSize)

        msg = _FFI.new('struct msghdr *')
        msg.msg_control = buf
        msg.msg_controllen = bufSize
        if iov is None:
            msg.msg_iov = _FFI.NULL
            msg.msg_iovlen = 0
        else:
            msg.msg_iov = iov
            msg.msg_iovlen = 1

        if oper is not None:
            header = _C.CMSG_FIRSTHDR(msg)
            header.cmsg_level = _C.SOL_ALG
            header.cmsg_type = _C.ALG_SET_OP
            header.cmsg_len = _C.CMSG_LEN(operSize)
            oper_ = _FFI.cast('uint32_t *', _C.CMSG_DATA(header))
            oper_[0] = oper

            if self.iv is not None:
                header = _C.CMSG_NXTHDR(msg, header)
                header.cmsg_level = _C.SOL_ALG
                header.cmsg_type = _C.ALG_SET_IV
                header.cmsg_len = ivMsgSize
                hIV = _FFI.cast('struct af_alg_iv *', _C.CMSG_DATA(header))
                hIV.ivlen = ivLength
                _FFI.buffer(hIV.iv, ivLength)[:] = self.iv

        if more:
            flags = _C.MSG_MORE
        else:
            flags = 0
                
        size = _C.sendmsg(self.fd, msg, flags)
        if size == -1:
            raise IOIfAlgError('Error in sendmsg', _FFI.errno)
                             
        return size
            
    def read(self, size):
        """Read data from the socket"""
        self._checkConnected()

        buf = _FFI.new('uint8_t[]', size)

        r = _C.read(self.fd, buf, size)
        if r == -1:
            return IOIfAlgError('Error in read', _FFI.errno)

        return _FFI.buffer(buf)[:]
        
    def send(self, data, more=False):
        """Send data to the socket"""
        out = _FFI.new('uint8_t[]', data)
        flags = _C.MSG_MORE if more else 0
        size = _C.send(self.fd, out, len(data), flags)
        if size == -1 :
            raise IOIfAlgError('Error in send', _FFI.errno)
        return size
