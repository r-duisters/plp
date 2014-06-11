#!/usr/bin/python

#   This file is part of Passive LAN Profiler.
#
#   Passive LAN Profiler is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   Passive LAN Profiler is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with Passive LAN Profiler.  If not, see <http://www.gnu.org/licenses/>.

import getopt
import logging
import re
import string
import sys
import os.path

# suppress the no IPv6 route warning in scapy when loading
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# import scapy
from scapy.all import *

# Import own modules
from lib.db import DB
from lib.report import Report
from lib.cdp import CDP
from lib.nbns import NBNS
from lib.dhcp import DHCPClass
from lib.stp import STPClass
from lib.smb import SMBClass
from lib.mdns import MDNSClass

class Passive(object):

    def __init__(self):
        self.logger = logging.getLogger('Passive.Main')
        self.initLogging()
        self.appversion = "0.1"
        self.tempDBFile = "Passive_DB.sqlite"
        self.reportfile = "Passive_report.pdf"

    def main(self):
        # The default database
        tempDBFile = self.tempDBFile 
        reportfile = self.reportfile

        try:
            # Check version
            if not re.match(r"2\.[2-9]\.\S*", config.conf.version):
                print "You are not running the latest scapy release."
                print "Please go to http://trac.secdev.org/scapy and follow the"
                print "the instructions to download the latest versions."
                sys.exit(1)

            # Set Variables for Options
            folder = None
            pcap_file = None
            pcap_files = []

            # Check if the options are given
            if len(sys.argv) == 1:
                self.usage()
                sys.exit(1)

            # Set Options
            options, remainder = getopt.getopt(sys.argv[1:], 'F:f:o:r:h')

            # Parse the options
            for opt, arg in options:
                if opt in ('-F'):
                    folder = arg
                elif opt in ('-f'):
                    pcap_file = arg
                elif opt in ('-o'):
                    tempDBFile = arg
                elif opt in ('-r'):
                    reportfile = arg
                elif opt in ('-h'):
                    self.usage()
                    sys.exit(1)
                else:
                    self.usage()
                    sys.exit(1)

            # Create the connection to the database
            self.db = DB(logging.getLogger('Passive.DB'), tempDBFile)

            # load the support for CDP Packets
            load_contrib("cdp")

            # Process folder with pcap files
            if folder:
                if os.path.isdir(folder):
                    for item in os.listdir(folder): 
                        fullpath = os.path.join(arg, item)
                        if os.path.isfile(fullpath) and ('.cap' in item or '.pcap' in item or '.dump' in item):
                            pcap_files.append(fullpath)
                else:
                    self.logger.error("Folder " + folder + " does not exist!")
                    sys.exit(1)


            # Process single pcap file
            if pcap_file:
                if os.path.isfile(pcap_file):
                    pcap_files.append(pcap_file)
                else:
                    self.logger.error("Pcap " + pcap_file + " does not exist!")
                    sys.exit(1)

            # Process all files selected and extract info
            packets = 0
            for f in pcap_files:
                try:
                    self.logger.info("Processing: " + f )
                    pcap = rdpcap(f)

                    # Get the name of the pcap
                    filename = f.split('/')
                    length = len(filename)
                    pcap_name = filename[length-1]
    
                    for p in pcap:
                        # Check if the packet is a CDP Packet
                        if Dot3 in p and p.dst == '01:00:0c:cc:cc:cc':
                            cdp = CDP(logging.getLogger('Passive.CDP'), self.db, pcap_name)
                            cdp.process_packet(p)
    
                        # Check if the packet is a NBNS Query Request packet
                        elif p.getlayer(NBNSQueryRequest):
                            nbns = NBNS(logging.getLogger('Passive.NBNS'), self.db, pcap_name)
                            nbns.process_packet(p)
    
                        # Check if the packet is a DHCP packet
                        elif p.getlayer(DHCP):
                            # Get the message type
                            for opt in p[DHCP].options:
                                # Get message type 8 (DHCP inform)
                                if (opt[0] == "message-type") and (opt[1] == 8):
                                    dhcp = DHCPClass(logging.getLogger('Passive.DHCP'), self.db, pcap_name)
                                    dhcp.process_packet(p)
                                # Get message type 5 (DHCP ack)
                                if (opt[0] == "message-type") and (opt[1] == 5):     
                                    dhcp = DHCPClass(logging.getLogger('Passive.DHCP'), self.db, pcap_name)   
                                    dhcp.process_packet(p)
    
                        # Check if the packet is a STP frame
                        elif p.getlayer(STP):
                            stp = STPClass(logging.getLogger('Passive.STP'), self.db, pcap_name)
                            stp.process_packet(p)
    
                        # Check if the packet is a NetBIOS datagram packet (SMB)
                        elif p.getlayer(NBTDatagram):
                            smb = SMBClass(logging.getLogger('Passive.SMB'), self.db, pcap_name)
                            smb.process_packet(p)
    
                        # Check if the packet is a Multicast DNS packet (MDNS)
                        try: # Using a try, since not every packet has a L3 destination
                            if p[IP].dst == "224.0.0.251":
                                mdns = MDNSClass(logging.getLogger('Passive.MDNS'), self.db, pcap_name)
                                mdns.process_packet(p)
                        except Exception, e:
                            pass

                # Print the (possible) exception of the first try statement
                except Exception, e:
                	print e
                	pass


            # Create the relations between the data
            self.logger.info("Creating relationships in the database")
            self.db.createRelations()

            # Write the database to a file, if a memory database is used
            if self.db.checkIfDBExists() != "True":
                self.db.sqLiteDumpMemDB()

            # Create report
            self.writeReport(reportfile)

            # Finished!
            self.logger.info("Finished!")

        except Exception, e:
            print e
            pass

    def writeReport(self, reportfile):
        self.logger.info("Generating the report (" + reportfile + ")")
        self.report = Report(logging.getLogger('Passive.Report'), self.db, reportfile, self.appversion)
        self.report.generateReport()

    def usage(self):
        """
        Function for presenting usage of the tool.
        """
        print "Passive Network Profiler v" + self.appversion + "\n "
        print "An tool that analyses a passively obtained PCAP file(s). The tool "
        print "presents information useful for the reconnaissance phase of a penetration " 
        print "test in a PDF report and a SQLite database. \n"
        print "main.py <OPTIONS>"
        print "-F <dir> \t\t Directory containing pcaps"
        print "-f <pcap> \t\t Pcap file"
        print "-o <outputDB> \t\t Output database file (" + self.tempDBFile + " default)"
        print "-r <outputReport> \t Output PDF report (" + self.reportfile + " default)"
        sys.exit(0)

    def initLogging(self):
        """Initialize logging module"""
        self.consoleLogHandler = logging.StreamHandler()
        self.consoleLogHandler.setFormatter(logging.Formatter('%(levelname)s\t| %(name)s | %(message)s'))
        self.consoleLogHandler.setLevel(logging.DEBUG)
        self.logger = logging.getLogger('Passive')
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(self.consoleLogHandler)


if __name__ == '__main__':
    passive = Passive()
    passive.main()
