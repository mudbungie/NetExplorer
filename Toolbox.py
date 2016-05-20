# Loose functions for doing things
import time
from datetime import datetime

def timestamp():
    # Returns the current time in epoch format.
    return time.mktime(datetime.now().timetuple())

