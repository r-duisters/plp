#!/usr/bin/python

import re
import string


class MDNSClass():

    def __init__(self, logging, db, pcap_name):
        self.logger = logging
        self.db = db
        self.pcap_name = pcap_name

    def process_packet(self, p):
        #self.logger.debug("MDNS packet found! " + p[IP].src)
        #self.logger.debug(len(p.load))
        list = []

        # We only want specific queries, that advertise the own hostname
        # Hence, we only want the responses

        bytes = hexstr(p.load).split(' ')
        # Choose the "Standard query response" MDNS packets, based on the flags
        if (bytes[2] == "84") and (bytes[3] == "00"):
            #print bytes
            # Select the "Answers" section
            answers = hexstr(p.load).split('.............')
            del answers[0]
            #print answers
            namesection = answers[0].split('........x')
            #self.logger.debug("MDNS response found! " + p[IP].src + " " + namesection[0])
            
        # _device-info string may be __very__ interesting!

        #Choose packet based on length
        #if (len(p.load) == 98) or (len(p.load) == 216):
            # That means the hostname is in the first spot
        #    hostname = bytes[0]
        #    self.logger.debug("MDNS packet found! " + p[IP].src + " " + hostname) 
        #else:
            #print len(p.load)
            #print " " 
            #print bytes
     
        #for byte in bytes:
            #print byte
            #regex = re.compile("{[a-zA-Z]*[\-].}")  
            #regex = re.compile("{\..[local]}")
            #regex = re.compile("[a-zA-Z0-9+_\-\.]")
            #regex = re.compile("[\.]")
            #print re.match('[a-zA-Z0-9+_\-\.]', byte)
            #if re.match(regex, byte):
                #if re.sub("..", "", byte):
            #        print "Apple name: ", byte

        #print list
