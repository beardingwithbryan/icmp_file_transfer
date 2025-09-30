from scapy.all import *

from tqdm import tqdm

import signal

import subprocess

import sys

import time

import re

import ipaddress

import argparse

from multiprocessing import Process

import netifaces

 

parser = argparse.ArgumentParser()

parser.add_argument('-i', '--iface', type=str, required=True, help="IP Address to listen on Information")

parser.add_argument('-f', '--file', required=True,

                            type=str,

                            dest='file',

                            help='File name to save data',

                            )

args = parser.parse_args()

 

message = []

 

def data_parser(packet_info):

 

    if packet_info.haslayer(ICMP):

        if packet_info[ICMP].type == 8 and packet_info[ICMP].id == 12312 and packet_info[Raw].load:

            byte_data = packet_info[Raw].load.decode('utf-8', errors="ignore").replace('\n', '')

            message.append(byte_data.replace("*", ""))

            if "*" in byte_data:

                print("file received")

                decoded_string = bytes.fromhex(''.join(message)).decode('utf-8')

                text_file = open(args.file, "w")

                text_file.write(decoded_string)

                text_file.close()

                exit()

 

def recv_info(iface, file_name):

    save_all = netifaces.interfaces()

    sniff(iface=f'{iface}', prn=data_parser, filter="icmp")

 

if __name__ == "__main__":

    recv_info(args.iface, args.file)
