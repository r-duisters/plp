#!/usr/bin/python
from scapy.all import *
import re
import string


class DHCPClass():

    def __init__(self, logging, db, pcap_name):
        self.logger = logging
        self.db = db
        self.pcap_name = pcap_name

    def process_packet(self, p):
        src_mac = p.src
        dst_mac = p.dst
        src_ip = p.getlayer(IP).src
        dst_ip = p.getlayer(IP).dst

        # Creating the variables, to make sure they are assigned before referencing
        message_type = ""
        lease_time = ""
        server_id = "" 
        subnet_mask = "" 
        router = "" 
        name_server = "" 
        ntp_server = "" 
        domain = "" 
        hostname = ""
        netbios_server = ""

        for opt in p[DHCP].options:
            if opt == "end":
                break
            elif opt == "pad":
                break
            elif opt[0] == "message-type":
                message_type = str(opt[1])
            elif opt[0] == "lease_time":
                lease_time = str(opt[1])
            elif opt[0] == "server_id":
                server_id = str(opt[1])
            elif opt[0] == "subnet_mask":
                subnet_mask = str(opt[1])
            elif opt[0] == "router":
                router = str(opt[1])
            elif opt[0] == "name_server":
                name_server = str(opt[1])
            elif opt[0] == "NTP_server":
                ntp_server = str(opt[1])
            elif opt[0] == "domain":
                domain = str(opt[1])
            elif opt[0] == "hostname":
                hostname = str(opt[1])
            elif opt[0] == "NetBIOS_server":
                netbios_server = str(opt[1])

        self.db.writeDHCP(self.pcap_name, src_mac, dst_mac, src_ip, dst_ip, message_type, lease_time, server_id, subnet_mask, router, name_server, ntp_server, domain, hostname, netbios_server)

