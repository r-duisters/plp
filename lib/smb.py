#!/usr/bin/python

import re
import string


class SMBClass():

    def __init__(self, logging, db, pcap_name):
        self.logger = logging
        self.db = db
        self.pcap_name = pcap_name

    def process_packet(self, p):

        if len(p.load) == 119: #Get the "Host announcement" queries
            bytes = hexstr(p.load).split(' ')

            self.flags = []

            #For the interesting flags, we only process the last 3 bytes of the flags
            flags_first_2_bytes = list(bin(int(bytes[110], 16)))

            # Splitting the first two bytes into the first and second byte
            first_2_bytes = bytes[110]
            first_byte = first_2_bytes[0]
            flags_first_byte = list(bin(int(first_byte, 16)))

            second_byte = first_2_bytes[1]
            flags_second_byte = list(bin(int(second_byte, 16)))

            # Only process the flags that exist.. 
            if len(flags_first_byte) > 2: 
                backup_controller = flags_first_byte[len(flags_first_byte)-1]
                backup_controller = self.ifTrue(backup_controller)
                if backup_controller:
                    self.flags.append("Backup Controller")
            if len(flags_first_byte) > 3: 
                time_source = flags_first_byte[len(flags_first_byte)-2]
                time_source = self.ifTrue(time_source)
                if time_source:
                    self.flags.append("Time source")
            if len(flags_first_byte) > 4: 
                apple = flags_first_byte[len(flags_first_byte)-3]
                apple = self.ifTrue(apple)
                if apple:
                    self.flags.append("Apple")
            if len(flags_first_byte) > 5: 
                novell = flags_first_byte[len(flags_first_byte)-4]
                novell = self.ifTrue(novell)
                if novell:
                    self.flags.append("Novell")

            # And the second byte
            if len(flags_second_byte) > 2: 
                workstation = flags_second_byte[len(flags_second_byte)-1]
                workstation = self.ifTrue(workstation)
                if workstation:
                    self.flags.append("Workstation")
            if len(flags_second_byte) > 3: 
                server = flags_second_byte[len(flags_second_byte)-2]
                server = self.ifTrue(server)
                if server:
                    self.flags.append("Server")
            if len(flags_second_byte) > 4: 
                sql = flags_second_byte[len(flags_second_byte)-3]
                sql = self.ifTrue(sql)
                if sql:
                    self.flags.append("SQL")
            if len(flags_second_byte) > 5: 
                domain_controller = flags_second_byte[len(flags_second_byte)-4]
                domain_controller = self.ifTrue(domain_controller)
                if domain_controller:
                    self.flags.append("Domain controller")

            # And on to the second two bytes
            second_2_bytes = bytes[111]
            third_byte = second_2_bytes[0]
            flags_third_byte = list(bin(int(third_byte, 16)))

            fourth_byte = second_2_bytes[1]
            flags_fourth_byte = list(bin(int(fourth_byte, 16)))

            if len(flags_third_byte) > 2: 
                nt_workstation = flags_third_byte[len(flags_third_byte)-1]
                nt_workstation = self.ifTrue(nt_workstation)
                if nt_workstation:
                    self.flags.append("NT Workstation")
            if len(flags_third_byte) > 3: 
                wfw = flags_third_byte[len(flags_third_byte)-2]
                wfw = self.ifTrue(wfw)
                if wfw:
                    self.flags.append("WFW")
            # The third one is unknown, skip
            if len(flags_third_byte) > 5: 
                nt_server = flags_third_byte[len(flags_third_byte)-4]
                nt_server = self.ifTrue(nt_server)
                if nt_server:
                    self.flags.append("NT Server")
            if len(flags_fourth_byte) > 2: 
                domain_member_server = flags_fourth_byte[len(flags_fourth_byte)-1]
                domain_member_server = self.ifTrue(domain_member_server)
                if domain_member_server:
                    self.flags.append("Domain member server")
            if len(flags_fourth_byte) > 3: 
                print_queue = flags_fourth_byte[len(flags_fourth_byte)-2]
                print_queue = self.ifTrue(print_queue)
                if print_queue:
                    self.flags.append("Print queue")
            if len(flags_fourth_byte) > 4: 
                dialin = flags_fourth_byte[len(flags_fourth_byte)-3]
                dialin = self.ifTrue(dialin)
                if dialin:
                    self.flags.append("Dialin")
            if len(flags_fourth_byte) > 5: 
                xenix = flags_fourth_byte[len(flags_fourth_byte)-4]
                xenix = self.ifTrue(xenix)
                if xenix:
                    self.flags.append("XenIX")

            # And on to byte 5 and 6
            third_2_bytes = bytes[112]
            fifth_byte = third_2_bytes[0]
            flags_fifth_byte = list(bin(int(fifth_byte)))

            sixth_byte = third_2_bytes[1]
            flags_sixth_byte = list(bin(int(sixth_byte)))

            if len(flags_fifth_byte) > 2: 
                osf = flags_fifth_byte[len(flags_fifth_byte)-1]
                osf = self.ifTrue(osf)
                if osf:
                    self.flags.append("OSF")
            if len(flags_fifth_byte) > 3: 
                vmf = flags_fifth_byte[len(flags_fifth_byte)-2]
                vmf = self.ifTrue(vmf)
                if vmf:
                    self.flags.append("VMF")
            if len(flags_fifth_byte) > 4: 
                win95 = flags_fifth_byte[len(flags_fifth_byte)-3]
                win95 = self.ifTrue(win95)
                if win95:
                    self.flags.append("Windows 95+")
            if len(flags_fifth_byte) > 5: 
                dfs = flags_fifth_byte[len(flags_fifth_byte)-4]
                dfs = self.ifTrue(dfs)
                if dfs:
                    self.flags.append("DFS")

            if len(flags_sixth_byte) > 2: 
                potential_browser = flags_sixth_byte[len(flags_sixth_byte)-1]
                potential_browser = self.ifTrue(potential_browser)
                if potential_browser:
                    self.flags.append("Potential browser")
            if len(flags_sixth_byte) > 3: 
                backup_browser = flags_sixth_byte[len(flags_sixth_byte)-2]
                backup_browser = self.ifTrue(backup_browser)
                if backup_browser:
                    self.flags.append("Backup browser")
            if len(flags_sixth_byte) > 4: 
                master_browser = flags_sixth_byte[len(flags_sixth_byte)-3]
                master_browser = self.ifTrue(master_browser)
                if master_browser:
                    self.flags.append("Master browser")
            if len(flags_sixth_byte) > 5: 
                domain_master_browser = flags_sixth_byte[len(flags_sixth_byte)-4]
                domain_master_browser = self.ifTrue(domain_master_browser)
                if domain_master_browser:
                    self.flags.append("Domain master browser")

            flagsstring = ", ".join(self.flags)

            self.db.writeSMB(self.pcap_name, p.src, p.SourceIP, p.SourceName, p.DestinationName, bytes[108], bytes[109], flagsstring)

    def ifTrue(self, nr):
        if nr == "1":
            return "True"
        else:
            return ""
