import socket
import psocket
from struct import unpack
from datetime import datetime
    
_packets = psocket.get_promiscuous_socket()

# This function sniffs data and immediately puts it on a queue to be
# processed. It does this so that it doesn't miss other incoming packets
# while processing the data or while waiting to receive the table from
# another channel. Note that in some circumstances packets will still not
# make it though. This could potentially happen if the OS doesn't assign
# this program enough thread time due to other bloated programs or general
# low performance. If a significant number of packets aren't making it,
# consider 1) whether something is taking too long in a critical section
# and 2) whether or not a second sniffer thread would work. In an early
# test case, this scaled well.
# 
def sniff(data_queue): 
    
    while True:
        ethernet_data, _ = _packets.recvfrom(65536)
        data_queue.put(ethernet_data)

