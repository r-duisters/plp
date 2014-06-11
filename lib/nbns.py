#!/usr/bin/python

import re
import string


class NBNS():

    def __init__(self, logging, db, pcap_name):
        self.logger = logging
        self.db = db
        self.pcap_name = pcap_name

    def process_packet(self, p):
        src_mac = p.src
        src_ip = p.getlayer(IP).src
        dst_ip = p.getlayer(IP).dst
        query = p.QUESTION_NAME
        self.db.writeNBNS(self.pcap_name, src_mac, src_ip, dst_ip, query)

