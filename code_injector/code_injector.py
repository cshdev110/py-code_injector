#!/usr/bin/env python

# Dependencies needed to manage netfilterqueue build-essential python<version>-dev libnetfilter-queue-dev
# After installing libnetfilter-queue-dev do not execute apt autoremove will break dependencies.
# Install module netfilterqueue as sudo
from netfilterqueue import NetfilterQueue
import argparse
import subprocess
import scapy.all as scapy


ack_list = []


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):  # DNS response
        if scapy_packet[scapy.TCP].dport == 80:
            if url_file.encode() in scapy_packet[scapy.Raw].load:
                print("[+] HTTP Request")
                print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] HTTP Response")
            print(scapy_packet.show())

    # print(scapy_packet.show())  # Return the packet's payload as a byte object to see the packets.
    packet.accept()  # If it is accepted, it will be forwarded.


def setting_iptables(option, chain):
    subprocess.run(['iptables', option, chain, '-j', 'NFQUEUE', '--queue-num', '0'])
    iptables_output = subprocess.run(['iptables', '-S'], capture_output=True).stdout.decode()
    # print(iptables_output)
    print(chain + " -j NFQUEUE --queue-num 0" in iptables_output and "Ok\r" or "Erased", end='\n')


def chain_setting(chain_iptables_to_set, remove):
    if chain_iptables_to_set in "forward" and not remove:
        print('Inserting ' + chain_iptables_to_set + ' chain -> ', end='')
        setting_iptables('-I', "FORWARD")
    elif chain_iptables_to_set in "localhost" and not remove:
        print('Inserting OUTPUT chain -> ', end='')
        setting_iptables('-I', 'OUTPUT')
        print('Inserting INPUT chain -> ', end='')
        setting_iptables('-I', 'INPUT')
    elif remove:
        if chain_iptables_to_set in "forward":
            print('\rRemoved ' + chain_iptables_to_set + ' chain -> ', end='')
            setting_iptables('-D', "FORWARD")
        elif chain_iptables_to_set in "localhost":
            print('\rRemoved OUTPUT chain -> ', end='')
            setting_iptables('-D', 'OUTPUT')
            print('\rRemoved INPUT chain -> ', end='')
            setting_iptables('-D', 'INPUT')


arguments = argparse.ArgumentParser(description="Intercepting file - HTTP only")
# arguments.add_argument('-f', '--file-type', dest='file_type', help='String which is the type of the file.')
arguments.add_argument('-c', '--iptables-chain', dest='chain_iptables', help='IPTABLES as forward or localhost')
arguments.add_argument('-url', '--url-file', dest='url_file', help='The url to swap the file requested for the other')

# file_type = arguments.parse_args().file_type
chain_iptables = arguments.parse_args().chain_iptables
url_file = arguments.parse_args().url_file


netQueue = NetfilterQueue()
try:
    netQueue.bind(0, process_packet)
    chain_setting(chain_iptables, False)
    netQueue.run()
except KeyboardInterrupt:
    chain_setting(chain_iptables, True)
except BaseException as be:
    print("\r[-] " + be.__str__() + " error has come up ... quiting", end='\n\n')
    chain_setting(chain_iptables, True)


netQueue.unbind()
