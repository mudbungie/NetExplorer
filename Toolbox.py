# Loose functions for doing things
import time
from datetime import datetime

def timestamp():
    # Returns the current time in epoch format.
    return time.mktime(datetime.now().timetuple())

def getUnique(iterable):
    if len(iterable) > 1:
        raise NonUniqueError('Expected unique', iterable)
    else:
        try:
            return iterable[0]
        except KeyError:
            return None


# Exceptions

class NonUniqueError(Exception):
    pass
