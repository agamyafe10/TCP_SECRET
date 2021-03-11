#use scapy
from scapy.all import *
import random as rnd
from hlp_funcs import *


def server_handshake():
    msg_parts = 0
    print("STARTED PROCCESS")
    SERVER_IP = '0.0.0.0'
    # sniffing for the furst SYN packet
    client_syn_packet = sniff(count=1, lfilter=syn_filter, timeout=30)
    if len(client_syn_packet) == 0:# in case no response 
        return -1
    client_syn_packet = client_syn_packet[0]

    # the recieved packet's details
    print("Got a syn packet")
    print(client_syn_packet.show())
    print(client_syn_packet['IP'].src)
    print(client_syn_packet['TCP'].dport)
    print(client_syn_packet['TCP'].sport)
    msg_parts = client_syn_packet[Raw].load
    # building and sending the SYN ACK packet
    syn_ack_segment = TCP(sport=client_syn_packet['TCP'].dport, dport=client_syn_packet['TCP'].sport, ack=client_syn_packet['TCP'].seq+1, seq=rnd.randint(1,1000), flags='SA')# after the syn packet sends another ack
    syn_ack_packet = IP(dst=SERVER_IP)/syn_ack_segment

    rcv_flag = False
    while not rcv_flag:
        send(syn_ack_packet)
        ack_packet = sniff(count=1,lfilter = ack_filter, timeout = 2)# send the first SYN packet
        print(ack_packet.show())
        print(len(ack_packet))
        if len(ack_packet) == 1:
            rcv_flag = True
            print("THREE WAY HANDSHAKE COMPLETED!")

    return msg_parts
