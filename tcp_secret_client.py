#use scapy
from scapy.all import *
import random as rnd
from hlp_funcs import *
import time

#constants
SERVER_IP = '0.0.0.0'#'192.168.1.13'


#THREE WAY HANDSHAKE
def client_handshake(spt, dpt, parts = None):
    syn_segment = TCP(sport=spt, dport=dpt, seq=rnd.randint(1,1000), flags='S')/Raw(load = str(parts))
    syn_packet = IP(dst=SERVER_IP)/syn_segment

    recieved = False
    # sending a SYN packet until getting an answer - a SYN ACK packet
    while not recieved:
        send(syn_packet)
        syn_ack_packet = sniff(count=1,lfilter = syn_ack_filter, timeout = 2)# send the first SYN packet
        print(syn_ack_packet.show())
        print(len(syn_ack_packet))
        if len(syn_ack_packet) == 1:
            recieved = True
            print("GOT A SYN ACK PACKET")
    
    # bulding and dending the final ACK packet
    syn_ack_packet = syn_ack_packet[0]
    ack_segment = TCP(sport=spt, dport=dpt, ack=syn_ack_packet['TCP'].seq+1, seq=int(syn_ack_packet['TCP'].ack), flags='A')# after the syn packet sends another ack
    ack_packet = IP(dst=SERVER_IP)/ack_segment
    send(ack_packet)
    print("ACK PACKET SENT!")

def chat_clinet():
    # recieving data from client
    msg = input("enter your message:\n")
    num = int(input("enter number of parts for the message:\n"))

    #there can't be more parts than letters in the message
    if num > len(msg):
        raise ValueError("there mustn't be more parts than length of message")

    # prepare the msg to be sent in parts
    msg_parts_dict = {}
    parts_length = int(len(msg)/num)
    part_seq = 0# used to know if there is a packet missing
    for i in range(num):
        part_seq += 10
        if i == num-1:
            current_part = msg
        else:
            current_part = msg[0:parts_length]
            msg = msg[parts_length:]
        msg_parts_dict[part_seq] = current_part

    for parts in msg_parts_dict.values():
        print('part: ' + parts)

    client_handshake(rnd.randint(60000, 62225), rnd.randint(60000, 62225), num)# send a num via the three way hanshake
    for seq_num in msg_parts_dict.keys():
        # sending each time te tect on a different port
        #optional - just to ensure that packet finding works
        # if msg_parts_dict[seq_num] != msg:# to check the mechanisam of the retrieving missing packets
            # source_port = rnd.randint(60000, 62225)
            # dest_port = rnd.randint(60000, 62225)
            # client_handshake(source_port, dest_port, 0)
            # time.sleep(1)# for the server to catch the msg packet
            # msg_packet = IP(dst=SERVER_IP)/TCP(sport=source_port, dport=dest_port, seq=seq_num)/Raw(load = msg_parts_dict[seq_num])
            # print("sent: "+ msg_parts_dict[seq_num])
            # send(msg_packet)
        source_port = rnd.randint(60000, 62225)
        dest_port = rnd.randint(60000, 62225)
        client_handshake(source_port, dest_port, 0)
        time.sleep(1)# for the server to catch the msg packet
        msg_packet = IP(dst=SERVER_IP)/TCP(sport=source_port, dport=dest_port, seq=seq_num)/Raw(load = msg_parts_dict[seq_num])
        print("sent: "+ msg_parts_dict[seq_num])
        send(msg_packet)
    print("sent all the message")
    # checking for a request to a missimg packet
    ask_missing = "decoy"
    # time.sleep(20)
    while len(ask_missing) != 0:# runs until does not get any request for missing packets
        ask_missing = sniff(count=1, lfilter=missing_packet_filter, timeout=7)
        if len(ask_missing) != 0:
            print("the missing seq is: " + str(ask_missing[0][TCP].seq))
            msg_packet = IP(dst=SERVER_IP)/TCP(sport=source_port, dport=dest_port, seq=seq_num)/Raw(load = msg_parts_dict[ask_missing[0][TCP].seq])
            send(msg_packet)