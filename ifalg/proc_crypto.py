"""Utilities to get Algorithm metadata parsing ``/proc/crypto``"""

from ifalg.alg_meta import AlgMeta
import bisect

def getAlgMeta(algName):
    """Return the metadata for a given Algorithm

    Returns:
      An AlgMeta instance
    
    Raises:
      ValueError if the algorithm was not found
    """
    meta = parseProcCrypto()
    try:
        #the last element is the one with the highest priority
        return meta[algName][-1]
    except KeyError:
        raise ValueError('Algorithm not found')

def parseProcCrypto():
    """ Parse ``/proc/crypto`` to gather algorithm metadata

    Returns:
      A dictionary in the form:
           { algName: [AlgMeta1, AlgMeta2, ....] }
      Where algName is the algorith name and each AlgMeta is the diferent
        versions of the algorithm ordered by priority.
    """
    response =  {}
    algName = None
    attrs = {}
    with open('/proc/crypto', 'r') as fd:
        for line in fd:
            line = line.strip()
            if line == '':
                if algName is not None:
                    alg = AlgMeta(algName, **attrs)
                    try:
                        #sorted insert
                        bisect.insort(response[algName], alg)
                    except KeyError:
                        response[algName] = [alg]

                algName = None
                attrs = {}
                continue
            
            name , value = line.split(':')
            name = name.strip()
            value = value.strip()
            if name == 'name':
                algName = value
            else:
                attrs[name] = value
            
        return response

