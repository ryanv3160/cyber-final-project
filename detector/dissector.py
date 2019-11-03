import socket
import psocket
from struct import unpack
from datetime import datetime
    
def dissect(data_queue, channel):

    while True:

        ethernet_data = data_queue.get()
        dst_mac, src_mac, protocol, data = ethernet_dissect(ethernet_data)
        
        print("the ethernet protocol is %s" % protocol)
        #print("the rest of the packet is %x" % data)
        if protocol == EthernetProtocol.ARP:
            arp_dissect(data)
        
        # table = channel.get()
        # key = (src_ip, dst_ip, dst_port)
        # if key not in table:
        #     table[key] = datetime.now()
        # channel.put(table)

        #if protocol == EthernetProtocol.IPV4:
        # ip_protocol, src_ip, dst_ip, transport_data = ipv4_dissect(ip_data)
        # IPProtocol.ICMP: icmp_type, icmp_code = icmp_dissect(transport_data)
        # IPProtocol.TCP:  src_port, dst_port, flags = tcp_dissect(transport_data)
        # IPProtocol.UDP:  src_port, dst_port = udp_dissect(transport_data)

class EthernetProtocol():
    IPV4 = 0x0008
    ARP = 0x0608

class IPProtocol():
    ICMP = 1
    TCP = 6
    UDP = 17

def ethernet_dissect(ethernet_data):
    dst_mac, src_mac, protocol = unpack('!6s 6s H', ethernet_data[:14])
    return mac_format(dst_mac), mac_format(src_mac), socket.htons(protocol), ethernet_data[14:]

def mac_format(mac):
    mac = map('{:02x}'.format, mac)
    return ':'.join(mac).upper()

def arp_dissect(arp_data):
    # TODO: Finish implementation
    
    # skip the hardware type
    # H is protocol type (ipv4)
    # skip the hardware and protocol size
    #   Hardware size is the number of bytes in the mac address.
    #   Protocol size is the number of bytes in the ip address
    #   I don't think there is any reason to suppose it won't be these two values.
    # H is ARP opcode
    protocol, opcode = unpack('!2x H 2x H', arp_data[:8])
    arp_data = arp_data[8:]
    print("the protocol is %s and the opcode is %s" % (protocol, opcode))

    # Even though we can normally assume the sizes will be 6 and 4, lets at least
    # verify the protocol type is IPv4 and not IPv6, so that we don't run into
    # any errors.
    if protocol == 0x0800:

        #sender_mac, sender_ip, target_mac, target_ip = unpack('!6B 4B 6B 4B', arp_data[:20])
        sender_mac, sender_ip, target_mac, target_ip = unpack('!6s 4s 6s 4s', arp_data[:20])
        print('sender mac: %s\nsender ip: %s\ntarget mac: %s\ntarget ip: %s' %
            (sender_mac, sender_ip, target_mac, target_ip))
    
    return arp_data

def ipv4_dissect(ip_data):
    ip_protocol, source_ip, target_ip = unpack('!9x B 2x 4s 4s', ip_data[:20])
    return ip_protocol, ipv4_format(source_ip), ipv4_format(target_ip), ip_data[20:]

def ipv4_format(address):
    return '.'.join(map(str, address))

def icmp_dissect(transport_data):
    icmp_type, code = unpack('!BB', transport_data[:2])
    return icmp_type, code

def tcp_dissect(transport_data):
    # skipping over the seq_num and ack_num in order to inspect the flags
    source_port, dst_port, flags = unpack('!HH 8x 1x B', transport_data[:14])
    return source_port, dst_port, flags

def udp_dissect(transport_data):
    source_port, dst_port = unpack('!HH', transport_data[:4])
    return source_port, dst_port

