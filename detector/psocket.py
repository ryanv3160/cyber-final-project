import socket
import ctypes
import fcntl

# Found out how to do this here: https://stackoverflow.com/q/6067405/9990099
class ifreq(ctypes.Structure):
        _fields_ = [("ifr_ifrn", ctypes.c_char * 16), ("ifr_flags", ctypes.c_short)]

IFF_PROMISC = 0x100
SIOCGIFFLAGS = 0x8913 # G for Get
SIOCSIFFLAGS = 0x8914 # S for Set

# I suppose I'll leave this in global memory in case someone wants to change the interface
ifr = ifreq()
ifr.ifr_ifrn = b'eth0'

def get_promiscuous_socket():
    # Note: AF_PACKET does not work on Mac, but works on Linux
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifr)
    ifr.ifr_flags |= IFF_PROMISC
    fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifr)
    return sock
    

