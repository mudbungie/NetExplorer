# This is a file that just parses the config
# Gives a dict-like object to anything that imports it

from configobj import ConfigObj
import os.path

whereAmI = os.path.dirname(os.path.abspath(__file__)) + '/'
config = ConfigObj(whereAmI + 'netexplorer.conf')
