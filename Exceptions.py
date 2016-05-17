# Gonna send updates when things throw unhandled errors...

class InputError(Exception):
    pass

class NonResponsiveError(Exception):
    pass

class RedundantHostError(Exception):
    pass
