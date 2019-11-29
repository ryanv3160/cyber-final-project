import arpreq
import ipaddress
from collections import defaultdict
import time

# Function to perform logic on intercepted arp messages
# This function launches on its own thread
def detect(channel, rate_time_threshold, rate_ips):

    # Dictionary for packet intercept
    # Format.....
    # [Key] = list()
    # [IP-Source IP-Destination] = Mac Source, Mac Destination, Timestamp, Timestamp, ... + .., Timestamp N
    # Note : time stamp occurrence keeps growing as we intercept packets from the same ip/ip key pairing. "For fan-out"
    dict_ips = defaultdict(list)


    # Dictionary for our custom Arp table
    # Format.....
    # [Key] = list()
    # [IP-Source] = Mac Source, Status
    # Note : The status has two values, either normal or abnormal for that entry. Abnormal if mac address is tied
    # to mutliple ip-address's or if fan-out rate of arp messages to update the victims arp table is achieved
    dict_arp_table = defaultdict(list)


    # Call function to perform Arp request
    arpRequest(dict_arp_table)
    # Call function to print our custom Arp Table
    printArpTable(dict_arp_table)

    # Main loop of the thread
    while True:
        # Only process packet in queue if there is a packet
        if not channel.empty():
            table = channel.get()
            # Make sure item from queue is not empty, "Leave this, for some reason first item is always blank"
            if len(table) > 0:
                # Make key of dictionary based on IP source and IP dest
                key = table[1] + " " + table[3]
                # If IP-IP pair is in the table, mean we have seen this arp packet before
                if key in dict_ips:
                    dict_ips[key].append(table[4])
                # Or this is a new occurrence so add it.
                else:
                    mac_tup = (table[0], table[2])
                    dict_ips[key].append(mac_tup)

                # Call function to determine if the IP intercepted is already in our table
                determineInArpTable(dict_arp_table, table[0], table[1])
                # Call function to determine if we meet threshold for fan-out rate for current packet intercepted
                determineFanout(dict_ips[key], rate_ips, rate_time_threshold)
                # Call function to perform Arp request for newly added IP to table, "IE check the provided mac with the real one"
                arpRequest(dict_arp_table)
                # Call function to print our custom Arp Table
                printArpTable(dict_arp_table)



# Function to perfomr the arp request to
def arpRequest(dict_arp_table):
    dict_mac = {}
    for ips in range(255):
        mac = arpreq.arpreq(ipaddress.IPv4Address(u'192.168.10.' + str(ips)))
        if mac is not None:
            dict_arp_table[str('192.168.10.' + str(ips))].append(mac)
            dict_arp_table[str('192.168.10.' + str(ips))].append("Normal")
            if str(mac) in dict_mac:
                for key in dict_arp_table.keys():
                    if dict_arp_table[key][0] == str(mac):
                        dict_arp_table[key][1] = "Abnormal"
                        print("Alert !! Duplicate entry found in ARP Table, Duplicate Mac: " + mac + " with IP: " + key)
                dict_mac[str(mac)] += 1

            else:
                dict_mac[str(mac)] = 1


# Function determines if packet intercepted is in out custom arp table
def determineInArpTable(dict_arp_table, mac, ip):

    # Ip already has entry in the table
    # Now check mac address is only tied to that IP and no other
    # Raise an alarm / alert to the user if we have the same mac address with mutliple Ip's
    if str(ip) in dict_arp_table:
        alarm = 0
        for key in dict_arp_table.keys():
            if dict_arp_table[key][0] == str(mac):
                alarm += 1

        # Found duplicate macs in table, update Status, and alert the user
        if alarm >= 2:
            print("Alert !! Duplicate entry found in ARP Table, Duplicate Mac: " + mac + " with IP: " + ip)
            for key in dict_arp_table.keys():
                if dict_arp_table[key][0] == str(mac):
                    dict_arp_table[key][1] = "Abnormal"
    else:
        # We have a new IP that is not in the table yet
        dict_arp_table[str(ip)].append(str(mac))
        dict_arp_table[str(ip)].append("Normal")
        alarm = 0
        for key in dict_arp_table.keys():
            if dict_arp_table[key][0] == str(mac):
                alarm += 1

        # Found duplicate in table, update Status
        if alarm >= 2:
            print("Alert !! Duplicate entry found in ARP Table, Duplicate Mac: " + mac + " with IP: " + ip)
            for key in dict_arp_table.keys():
                if dict_arp_table[key][0] == str(mac):
                    dict_arp_table[key][1] = "Abnormal"


# Function Prints the Modified Arp table we have constructed
def printArpTable(dict_arp_table):
    print("***************** ARP Table *****************")
    print("IP Address\t\tMac Address\t\t\tStatus")
    for key in dict_arp_table:
        print(key + "\t" + dict_arp_table[key][0] + "\t" + dict_arp_table[key][1])
    print("*********************************************")


# Function calculates the fan-out rate for intercepting the same IP to IP Arp message
# This is a trigger to being spoofed since the attacker must keep updating the victims ARP routing table
def determineFanout(packet, rate_ips, rate_time_threshold):

    # Curent time and zero intercept count
    current_time = time.time()
    count = 0

    # Math since the first entry in the constructed packet is mac to mac pairing,
    # everything else are timestamps
    time_stamp_count = len(packet) - 1

    # First check that the amount of timestamps received for the IP pairing are greater than the count.
    # or else we would not even make the fan-out threshold
    if time_stamp_count >= rate_ips:

        # Loop through all timestamps associated with the IP pairing
        for timestamps in range(rate_ips):

            # If the stamp is within the last "rate_time_threshold"
            if (current_time - packet[time_stamp_count - timestamps]) < rate_time_threshold:
                count += 1

    # If we have an excedence then alert user
    if count == rate_ips:
        print("Alert !! Fan out rate reached : " + str(rate_ips) + " requests, over the course of : " + str(rate_time_threshold) + " seconds")

