"""Low level communications with linux AF_ALG sockets"""

from cffi import FFI
from ifalg import utils
from ifalg.proc_crypto import getAlgMeta
import os
import logging 
import errno

log = logging.getLogger(__name__)

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
#define PAGE_SIZE ...

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

int pipe(int pipefd[2]);
int socket(int domain, int type, int protocol);
int bind(int sockfd, struct sockaddr *addr, socklen_t addrlen);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int close(int fd);
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t read(int fd, void *buf, size_t count);
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);

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

//SPLICE
#define SPLICE_F_MORE ...
#define SPLICE_F_GIFT ...

typedef ... loff_t;
ssize_t vmsplice(int fd, const struct iovec *iov,
                 unsigned long nr_segs, unsigned int flags);
ssize_t splice(int fd_in, loff_t *off_in, int fd_out,
               loff_t *off_out, size_t len, unsigned int flags);

""")

_C = _FFI.verify("""
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/user.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

""", libraries=[])

#Algorithm types
#aead and rng are not supported yet
ALG_TYPE_SKCIPHER = 'skcipher'
ALG_TYPE_HASH = 'hash'
ALG_TYPES = [ALG_TYPE_SKCIPHER, ALG_TYPE_HASH]

STRATEGY_HEURISTIC = 1
STRATEGY_SENDMSG = 2
STRATEGY_SPLICE = 3
STRATEGY_ALL = (STRATEGY_HEURISTIC,
                STRATEGY_SENDMSG,
                STRATEGY_SPLICE)

HEURISTIC_SPLICE_LIMIT = 8192
MAXPIPELEN = 16 * _C.PAGE_SIZE

class IfAlgError(Exception):
    """Base error class"""
    pass

class InvalidStateError(IfAlgError):
    """Raised when the agorithm is not ready for an operation"""
    pass

class InvalidAlgError(IfAlgError):
    """Raised when an algorithm does not exists"""
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
    def __init__(self, algType, algName, key=None, iv=None, strategy=STRATEGY_HEURISTIC):
        """Initializes a crypto API algorithm

        Args:
          algType (str): Algorithm type, valid values are: ALG_TYPE_SKCIPHER and ALG_TYPE_HASH
          algName (str): Algorithm name
          key (bytes, optional): Algorithm key if necesary, default is None
          iv  (bytes, optional): Algorithm Initial vector, default is None
          strategy (int, optional): data feeding strategy for the sendData method, must be one of:
              STRATEGY_SENDMSG: Send all data at once using the sendmsg system call.
              STRATEGY_SPLICE: Send data in chunks using splice/vmsplice system calls.
              STRATEGY_HEURISTIC: Use sendmsg if data > 8KBs, else use splice, this is the default.

        Raises:
          ValueError: For invalid parameters
        """
        if algType not in ALG_TYPES:
            raise ValueError('algType not supported: %s'%(algType,))
        if algType is None:
            raise ValueError('algType is required')
        if algName is None:
            raise ValueError('algName is required')

        if strategy not in STRATEGY_ALL:
            raise ValueError('Invalid strategy')
        self.strategy = strategy

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

        #pipes for splice strategy
        if strategy in (STRATEGY_HEURISTIC, STRATEGY_SPLICE):
            self._createPipe()
        else:
            self.pipe = None

        #buffer to keep alive memory for splice operations
        self.splicebuffer = None
        
        #algorithm metadata
        self.meta = None

    def _createPipe(self):
        """Create pipes to use with splice/vmsplice"""
        self.pipe = _FFI.new('int[]', 2)
        r = _C.pipe(self.pipe)
        if r == -1:
            raise IOIfAlgError('Error creating pipe', _FFI.errno)

    def _connect(self):
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
                if _FFI.errno == errno.ENOENT:
                    raise InvalidAlgError('Invalid algorithm: %s'%(self.algName,))
                raise IOIfAlgError('Error binding socket', _FFI.errno)

            self.fd = _C.accept(self.sockfd, _FFI.NULL, _FFI.NULL)
            if self.fd == -1:
                raise IOIfAlgError('Error during socket accept', _FFI.errno)
        finally:
            try:
                if self.fd > 0:
                    _C.close(fd)
            except:
                pass

            try:
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

        if self.pipe:
            _C.close(self.pipe[1])
            _C.close(self.pipe[0])

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
        

    def _sendmsg(self, data=None, encrypt=True, more=False):
        """Low level data sending using sendmsg system call

        Args:
          data (bytes, optional): Raw data to send (default: None)
          encrypt (boolean, optional): True to encrypt, False to decrypt.
              if set to None the operation type and the IV are not send. Default is True.
          more (boolean, optional) True to include the MSG_MORE flag, default is False.

        Returns:
          int: number of bytes send.

        Raises:
          InvalidStateError: if not connected
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
        msg.msg_flags = 0
        msg.msg_name = _FFI.NULL
        msg.msg_namelen = 0
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
        #log.debug('calling sendmsg(msg(name:%r, namelen:%r, iov:%r, iovlen:%r, control:%r, controllen:%r, flags:%r), flags:%r)',
        #          msg.msg_name, msg.msg_namelen, msg.msg_iov, msg.msg_iovlen, msg.msg_control, msg.msg_controllen, msg.msg_flags, flags)
        size = _C.sendmsg(self.fd, msg, flags)
        if size == -1:
            raise IOIfAlgError('Error in sendmsg', _FFI.errno)
                             
        return size
            
    def _read(self, size):
        """Read data from the socket

        Returns:
          bytes: Data readed
          
        Args:
          size (int): amount of data to read.

        """
        self._checkConnected()

        buf = _FFI.new('uint8_t[]', size)

        r = _C.read(self.fd, buf, size)
        if r == -1:
            raise IOIfAlgError('Error in read', _FFI.errno)

        if self.splicebuffer:
            #gc splice buffer
            self.splicebuffer = None
        
        return _FFI.buffer(buf)[:]

    def _recvmsg(self, size):
        """Low level call to recvmsg

        Args:
          size (int): Number of bytes to read.

        Returns
          bytes: Data readed.
        """
        buf = _FFI.new('uint8_t[]', size)
        iov = _FFI.new('struct iovec *')
        iov.iov_base = buf
        iov.iov_len = size
        msg = _FFI.new('struct msghdr *')
        msg.msg_name = _FFI.NULL
        msg.msg_namelen = 0
        msg.msg_control = _FFI.NULL
        msg.msg_controllen = 0
        msg.msg_iov = iov
        msg.msg_iovlen = 1
        msg.msg_flags = 0
        r = _C.recvmsg(self.fd, msg, 0)
        if r == -1:
            raise IOIfAlgError('Error in recvmsg', _FFI.errno)

        return _FFI.buffer(buf)[:]
        
    def _send(self, data, more=False):
        """low level call to send system call
        
        Args:
          data (bytes): Data to send.
          more (boolean, optional): True to include MSG_MORE flag, default is False

        Returns:
          int: The amount of data sended
        """
        out = _FFI.new('uint8_t[]', data)
        flags = _C.MSG_MORE if more else 0
        size = _C.send(self.fd, out, len(data), flags)
        if size == -1 :
            raise IOIfAlgError('Error in send', _FFI.errno)
        return size


    def _splice(self, data):
        """Send data to the socket using vmsplice/splice system calls

        Args:
          data (bytes): Data to send
        
        Returns:
          int: The amount of data sended
        """
        dataLength = len(data)
        remainingLength = dataLength
        offset = 0
        iov = _FFI.new('struct iovec *')
        flags = _C.SPLICE_F_MORE
        self.splicebuffer = _FFI.new('uint8_t[]', data)
        while remainingLength:
            sendLength = MAXPIPELEN if remainingLength > MAXPIPELEN else remainingLength
            iov.iov_base = _FFI.addressof(self.splicebuffer, offset)
            iov.iov_len = sendLength
            rSend = _C.vmsplice(self.pipe[1], iov, 1, flags)
            if rSend == -1:
                raise IOIfAlgError("Error in vmsplice", _FFI.errno)
            if rSend != sendLength:
                log.warning("vmsplice: not all data received by kernel, sended:%d, received:%d", sendLength, rSend)

            rSend = _C.splice(self.pipe[0], _FFI.NULL, self.fd, _FFI.NULL, rSend, flags)
            if rSend == -1:
                raise IOIfAlgError("Error in splice", _FFI.errno)

            remainingLength -= rSend
            offset += rSend

        return dataLength


    def sendData(self, data, encrypt=None):
        """Send data to the algorithm using the current strategy
        
        Args:
          data (bytes): Data to send
          encrypt: True to encrypt, False to decrypt and None to only send data to the socket

        Returns:
          int: The amount of data sended
        """

        #logic adapted from libkcapi
        # for large data splice should be faster
        dataLen = len(data)
        if ((self.strategy == STRATEGY_HEURISTIC
                and dataLen <= HEURISTIC_SPLICE_LIMIT)
                or self.strategy == STRATEGY_SENDMSG):
            return self._sendmsg(data, encrypt=encrypt)
        else:
            if encrypt != None:
                #send options: encrypt/decrypt and IV
                self._sendmsg(None, encrypt=encrypt)
            return self._splice(data)

