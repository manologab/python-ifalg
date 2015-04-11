class AlgMeta:
    """Algorithm metadata, it is currently obtained from /proc/crypto
       
      In the future it will be queried using NETLINK_CRYPTO (kernel >= 3.2)
    """

    #some names must be replaced to be valid python attribute names
    NAME_REPLACE = {
        'type': 'algType', #'type' is not a reserved keyword in python, but...
        'min keysize': 'minKeysize',
        'max keysize': 'maxKeysize'
    }

    def __init__(self, algName, **kwargs):
        self.algName = algName

        for (name, value) in kwargs.items():
            #name replacements
            if name in self.NAME_REPLACE:
                name = self.NAME_REPLACE[name]

            #numeric values
            if name in ['priority', 'refcnt', 'blocksize', 'seedsize',
                        'minKeysize', 'maxKeysize', 'digestsize', 'ivsize',
                        'maxauthsize']:
                value = int(value)

            setattr(self, name, value)

    #Order algorithms by priority
    def __lt__(self, x):
        return self.priority < x.priority

    def __le__(self, x):
        return self.priority <= x.priority

    def __gt__(self, x):
        return self.priority > x.priority

    def __ge__(self, x):
        return self.priority >= x.priority

    def __str__(self):
        return repr(self.__dict__)

    def __repr__(self):
        return repr(self.__dict__)
