#!/usr/bin/env python3

from threading import Thread
from queue import Queue
from time import sleep
import sys

from sniffer import sniff
from dissector import dissect
from detector import detect

def main():
    
    # Using queues for synchronization and data control
    data_queue = Queue()
    channel = Queue()
    table = {}
    channel.put(table)


    rate_time_threshold, rate_ips = commandLineParser()
    
    print("ARP Spoofer detector initialized")
    print("press [Ctrl+C] to quit")
    sniffer = Thread(target=sniff, args=(data_queue,)) 
    dissector = Thread(target=dissect, args=(data_queue, channel))
    detector = Thread(target=detect, args=(channel, rate_time_threshold, rate_ips))
     
    sniffer.daemon = True
    dissector.daemon = True
    detector.daemon = True
    
    sniffer.start()
    dissector.start()
    detector.start()

    try:
        while True: pass
    except KeyboardInterrupt:
        print()

    '''
    try:
        # Proof of concept showing we can fetch items from the queue
        # Note: later we may as well replace this with a call to one of the other functions
        num = 0
        while True:
            table = channel.get()
            size = len(table)
            if size != num:
                more_or_less = "more" if size > num else "less"
                print("we now have %d %s entries (total = %d)" % (abs(size - num), more_or_less, size))
                num = size
            channel.put(table)
        
    except KeyboardInterrupt:
        print()
    '''

def commandLineParser():
    if len(sys.argv) < 2:
        print("Missing command line arguments")
    return sys.argv[0], sys.argv[1]

if __name__ == "__main__": 
    main()

