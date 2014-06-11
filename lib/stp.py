#!/usr/bin/python

import re
import string


class STPClass():

    def __init__(self, logging, db, pcap_name):
        self.logger = logging
        self.db = db
        self.pcap_name = pcap_name

    def process_packet(self, p):
        src_mac = str(p.src)
        version = str(p.version)
        bpdutype = str(p.bpdutype)
        rootid = str(p.rootid)
        rootmac = str(p.rootmac)
        pathcost = str(p.pathcost)
        bridgeid = str(p.bridgeid)
        bridgemac = str(p.bridgemac)
        portid = str(p.portid)
        age = str(p.age)
        maxage = str(p.maxage)
        hellotime = str(p.hellotime)
        fwddelay = str(p.fwddelay)

        self.db.writeSTP(self.pcap_name, src_mac, version, bpdutype, rootid, rootmac, pathcost, bridgeid, bridgemac, portid, age, maxage, hellotime, fwddelay)





