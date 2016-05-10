# Represents a network interface

from NetworkPrimitives import Mac, Ip

class Interface:
    def __init__(self, mac):
       # Every interfaces has a MAC.
       # Use Mac subclass for validation.
       self.mac = Mac(mac)

    def __str__(self):
        return self.mac.__str__()

    # Publicly get-and-settable IP attribute with validation
    @property
    def ip(self):
        return self.__ip
    @ip.setter
    def ip(self, ip):
        self.__ip = Ip(ip)
    # Publicly get-and-settable label attribute
    @property
    def label(self):
        return self.__label
    @label.setter
    def label(self, label):
        self.__label = label
    # Publicly get-and-settable speed attribute
    @property
    def speed(self):
        return self.__speed
    @speed.setter
    def speed(self, speed):
        self.__speed = speed
