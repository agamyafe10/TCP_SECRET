from scapy.all import *
import random as rnd
import math
def syn_filter(packet):
    """filter syn packets for the three way handshake

    Args:
        packet ([type]): [description]

    Returns:
        [type]: [description]
    """
    return TCP in packet and IP in packet and packet[TCP].flags == 'S' and packet[TCP].dport > 60000


def syn_ack_filter(packet):
    return tcp_filter(packet) and packet['TCP'].flags == 'SA' and packet['TCP'].dport > 60000


def filter_by_ip(packet):
    SERVER_IP = '192.168.1.13'
    return int(packet['TCP'].dport) == 40500 #and packet['IP'].dst == SERVER_IP


def ack_filter(packet):
    return TCP in packet and IP in packet and packet[TCP].flags == 'A' and packet[TCP].dport > 60000


def tcp_filter(packet):
    return 'TCP' in packet #and 'IP' in packet


def msg_filter(packet):
    # print(packet[Raw].load)
    return TCP in packet and IP in packet and packet[TCP].dport > 60000 and not packet[Raw].load.decode().isnumeric()
    
def missing_packet_filter(packet):
    # print(packet[Raw].load)
    return TCP in packet and IP in packet and packet[TCP].dport > 60000 
# SERVER_IP = '0.0.0.0'#'192.168.1.13'
# # msg_packet = IP(dst=SERVER_IP)/TCP(sport=60100, dport=60200, seq=rnd.randint(1,1000))/Raw(load = "ack")
# # print(msg_filter(msg_packet))
# # syn_segment = TCP(sport=60100, dport=60200, seq=rnd.randint(1,1000), flags='S')/Raw(load = '2')
# # syn_packet = IP(dst=SERVER_IP)/syn_segment
# # print(msg_filter(syn_packet))
# get_missing_packet = IP(dst=SERVER_IP)/TCP(sport=rnd.randint(60000, 62225), dport=rnd.randint(60000, 62225), seq=30)
# print(missing_packet_filter(get_missing_packet))