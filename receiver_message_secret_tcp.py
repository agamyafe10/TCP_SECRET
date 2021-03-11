from scapy.all import *
from hlp_funcs import *
import random as rnd
import time
from tcp_secret_server import server_handshake
# from tcp_secret_client import client_handshake

def is_missing_packet(dicts, parts_num):
    """
    finds the seq number of the missing meassage part(they are order in tens)

    Args:
        dicts (dictionary): keys - seq, values - message parts
        parts_num (int): the real amount of message parts

    Returns -1 if thre is no one misiing or the seq num of the missing part
    """
    for seq in range(10, (parts_num + 1)*10, 10):
        part = dicts.get(seq, -1)
        if part == -1:
            return seq
    return -1

def chat_server():
    #constants
    SERVER_IP = '0.0.0.0'

    msg = {}
    parts_length = int(server_handshake())
    print("got a length!")
    print("number of parts: " + str(parts_length))
    while True:
        if len(msg) == parts_length:
            break
        to_cntn = server_handshake()# to check if there is a part missing
        if to_cntn == -1:# if thre was a missing part
            missing_packet_seq = is_missing_packet(msg, parts_length)
            get_missing_packet = IP(dst=SERVER_IP)/TCP(sport=rnd.randint(60000, 62225), dport=rnd.randint(60000, 62225), seq=missing_packet_seq)# send a packet which his seq is the seq of the missing packet's seq number
            send(get_missing_packet)
            print("waiting for missing packet: " + str(missing_packet_seq))
            
        packets = sniff(count = 1, lfilter = msg_filter)
        packets = packets[0]
        print(packets.show())
        if Raw in packets:
            print('I LOVE YOU: ' + str(packets[Raw].load))
            msg[packets[TCP].seq] = str(packets[Raw].load)[2:].split("'")[0]

    msg_sorted = sorted(msg.keys())# if thre was a problem with the order of the recieved packets
    my_str = ""
    for part in msg_sorted:
        my_str += msg[part]

    print("the message is: " + my_str)
