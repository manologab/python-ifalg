import six

def strToBytes(data):
    """Returns the data as valid binary sequence

    Returns:
      bytes
    """
    
    if isinstance(data, six.string_types):
        return data.encode('ascii')

    if six.PY3 and isinstance(data, bytes):
        return data

    raise ValueError('data must be str or bytes')
    
