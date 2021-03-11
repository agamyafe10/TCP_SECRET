from scapy.all import *
import random as rnd
from hlp_funcs import *
import time
from tcp_secret_client import *
from receiver_message_secret_tcp import *

state = True# true means client mode false means server mode
cntn = 1
while cntn == 1:
    if state:
        chat_clinet()
        state = False
    else:
        chat_server()
        state = True
    cntn = int(input("enter 1 to proceed the chatting or press any other key to end the chat - \n"))