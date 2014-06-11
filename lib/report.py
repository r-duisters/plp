import sys
import string
from reportlab.platypus import *
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.rl_config import defaultPageSize

class Report():
    """

    """

    def __init__(self, logger, db, outputfile, appversion):
        ""
        self.logger = logger
        self.db = db
        self.outputfile = outputfile
        self.appversion = appversion

    def generateReport(self):
        from reportlab.lib.units import inch

        PAGE_HEIGHT=defaultPageSize[1]
        styles = getSampleStyleSheet()


        # Getting the PCAPS, used for this report..
        UsedPCAPS = self.db.executeQuery("SELECT DISTINCT src_pcap FROM system;")
        PCAPlist = []

        for UsedPCAP in UsedPCAPS:
            PCAPlist.append(UsedPCAP[0] + " \n")
        UsedPCAPstring = ''.join(PCAPlist)

        # Checking if we should write "file" or "files"
        if len(UsedPCAPS) == 1:
            filestring = "PCAP file: "
        else:
            filestring = str(len(UsedPCAPS)) + " PCAP files: "

        Abstract = "This report shows the information, gathered by the Passive LAN Profiler application. The report contains information gathered from the following " + filestring + UsedPCAPstring


        def myFirstPage(canvas, doc):
            canvas.saveState()
            #canvas.setStrokeColorRGB(1,0,0)
            #canvas.setLineWidth(5)
            #canvas.line(66,72,66,PAGE_HEIGHT-72)
            canvas.setFont('Times-Bold',16)
            #canvas.drawString(108, PAGE_HEIGHT-108, Title)
            canvas.setFont('Times-Roman',9)
            #canvas.drawString(inch, 0.75 * inch, "First Page / %s" % pageinfo)
            canvas.restoreState()

        def myLaterPages(canvas, doc):
            #canvas.drawImage("snkanim.gif", 36, 36)
            canvas.saveState()
            #canvas.setStrokeColorRGB(1,0,0)
            #canvas.setLineWidth(5)
            #canvas.line(66,72,66,PAGE_HEIGHT-72)
            canvas.setFont('Times-Roman',9)
            #canvas.drawString(inch, 0.75 * inch, "Page %d %s" % (doc.page, pageinfo))
            canvas.restoreState()

        def go():
            Elements.insert(0,Spacer(0,inch))
            doc = SimpleDocTemplate(self.outputfile)
            doc.build(Elements,onFirstPage=myFirstPage, onLaterPages=myLaterPages)

        Elements = []

        HeaderStyle = styles["Heading1"] 

        def header(txt, style=HeaderStyle, klass=Paragraph, sep=0.3):
            s = Spacer(0.2*inch, sep*inch)
            Elements.append(s)
            para = klass(txt, style)
            Elements.append(para)

        ParaStyle = styles["Normal"]

        def p(txt):
            return header(txt, style=ParaStyle, sep=0.1)

        PreStyle = styles["Code"]

        def pre(txt):
            s = Spacer(0.1*inch, 0.1*inch)
            Elements.append(s)
            p = Preformatted(txt, ParaStyle)
            Elements.append(p)


        # The following three functions are needed to calculate the VLAN from Cisco's proprietary PVSTP implementation. 
        def RootIDContainsVLAN(self, rootid):
            vlannr = int(rootid) % 4096
            if vlannr != 0:
                return "True"

        def GetRootIDVlan(self, rootid):
            vlannr = int(rootid) % 4096
            if vlannr != 0:
                return vlannr

        def GetOriginalRootID(self, rootid):
            vlannr = GetRootIDVlan(self, rootid)
            original_rootid = int(rootid) - int(vlannr)
            return original_rootid

        # Start printing information in the PDF

        header("Passive LAN Profiler v" + str(self.appversion))
        p(Abstract)

        # Selecting all sources to loop through the networks (PCAPs)
        sources = self.db.executeQuery("SELECT DISTINCT src_pcap FROM system;")
        i = 0
        for source in sources:
            src_pcap = source[0]

            # Counting the amount of nodes
            amountofnodes = self.db.executeQuery("SELECT Count(*) FROM system where src_pcap='" + src_pcap +"';")
            stripped_nodes = str(amountofnodes[0]).strip('\'u(),"')
            if int(stripped_nodes) == 1: 
                nodes_string = " - " + str(stripped_nodes) + " node"
            else:
                nodes_string = " - " + str(stripped_nodes) + " nodes"

            # Counting the amount of IP subnets
            amountofsubnets = self.db.executeQuery("SELECT Count(*) FROM network where src_pcap='" + src_pcap +"';")
            stripped_subnets = str(amountofsubnets[0]).strip('\'u(),"')
            if int(stripped_subnets) == 1: 
                subnets_string = " - " + str(stripped_subnets) + " IP subnet"
            else:
                subnets_string = " - " + str(stripped_subnets) + " IP subnets"


            # Indicate the network & pcap we are working from
            header("Network " + string.ascii_uppercase[i] + nodes_string + subnets_string)
            p("Observed in: " + src_pcap)

            # Get the L2 information
            # First, print VLAN information
            cdp = self.db.executeQuery("select native_vlan, voip_vlan from cdp where cdp.src_pcap='" + str(src_pcap) + "';")
            foundCDPInfo = "" # Reference var, before assignment

            for cdp_entry in cdp:
                native_vlan = cdp_entry[0]
                voip_vlan = cdp_entry[1]
                foundCDPInfo = "True"

            if foundCDPInfo:
                # If the network has a VLAN, print
                if native_vlan != "": 
                    p("VLAN: " + str(native_vlan) ) 
                    # Else, we may be able to use STP for the VLAN ID                            
                # Voice VLAN
                if voip_vlan != "":
                    p("VoIP VLAN: " + str(voip_vlan)) 
            else:   # Check STP for VLAN information
                    # Cisco's PVSTP implementation added a value to the root id, to differentiate between VLANs
                stp = self.db.executeQuery("select rootid from stp where src_pcap='" + str(src_pcap) + "';")

                # If multiple STP instances are found, notify
                if int(len(stp)) > 1: 
                    p(str(len(stp)) + " connected VLANs found (obtained by STP):")

                for stp_entry in stp:
                    rootid = stp_entry[0]
                    if (len(str(rootid)) != 0): 
                    # Can be printed multiple times, since STP may be received multiple times (current and VOICE VLAN)
                        sanitized_rootid = str(rootid).strip('\'u(),"')
                        if RootIDContainsVLAN(self, sanitized_rootid):
                            vlannr = GetRootIDVlan(self, sanitized_rootid)
                            pre("     Connected VLAN: " + str(vlannr)) 


            # Gather information about the connected bridge/switch

            # Gather the STP information
            stp = self.db.executeQuery("select src_mac, version, rootid, rootmac, pathcost, bridgeid, bridgemac, portid, age, maxage, hellotime, fwddelay from stp where src_pcap='" + str(src_pcap) + "';")
            foundSTPInfo = "" # Reference var, before assignment
            for stp_entry in stp: 
                stp_src_mac = stp_entry[0]
                # If an STP entry has been found, we set foundSTPInfo to True. 
                foundSTPInfo = "True"

            # Gather the CDP information
            cdp = self.db.executeQuery("select device_id, platform, ip_addr, software_version, port_id, capabilities, native_vlan, voip_vlan, ip_prefix, power, power_available, src_mac from cdp where cdp.src_pcap='" + str(src_pcap) + "';")
            foundCDPInfo = "" # Reference var, before assignment. Done again for neatness. 
            for cdp_entry in cdp:
                device_id = cdp_entry[0]
                platform = cdp_entry[1]
                ip_addr = cdp_entry[2]
                software_version = cdp_entry[3]
                port_id = cdp_entry[4]
                capabilities = cdp_entry[5]
                native_vlan = cdp_entry[6]
                voip_vlan = cdp_entry[7]
                ip_prefix = cdp_entry[8]
                power = cdp_entry[9]
                power_available = cdp_entry[10]
                cdp_src_mac = cdp_entry[10]
                foundCDPInfo = "True"

            # Checking the source MAC addresses of the connected bridge. 
            if 'stp_src_mac' in locals():
                src_mac = stp_src_mac
            elif 'cdp_src_mac' in locals():
                src_mac = cdp_src_mac

            # If we have STP or CDP info, we have information about the connected bridge
            if foundSTPInfo or foundCDPInfo:
                    p("Connected bridge (MAC address: " + str(src_mac) + "):") 

            if foundCDPInfo:
                # Print, but only if this information has been found
                if device_id != "":
                    pre("     Device ID (hostname): " + str(device_id))
                if platform != "":
                    pre("     Hardware platform: " + str(platform))
                if ip_addr != "":
                    pre("     Management IP address: " + str(ip_addr))
                if software_version != "":
                    pre("     Software version: " + str(software_version))
                if port_id != "":
                    pre("     Connected port ID: " + str(port_id))
                if capabilities != "":
                    pre("     Device capabilities: " + str(capabilities))
                if ip_prefix != "":
                    pre("     IP prefix: " + str(ip_prefix))
                if power != "":
                    pre("     Power: " + str(power))
                if power_available != "":
                    pre("     Power available (PoE): " + str(power_available))


            # Reference before assignment
            MultipleInstances = ""

            # Write a line when multiple STP instances are found
            if int(len(stp)) > 1: 
                p(str(len(stp)) + " STP instances found:")
                MultipleInstances = "True"

            for stp_entry in stp:
                src_mac = stp_entry[0]
                version = stp_entry[1]
                rootid = stp_entry[2]
                rootmac = stp_entry[3]
                pathcost = stp_entry[4]
                bridgeid = stp_entry[5]
                bridgemac = stp_entry[6]
                portid = stp_entry[7]
                age = stp_entry[8]
                maxage = stp_entry[9]
                hellotime = stp_entry[10]
                fwddelay = stp_entry[11]
                foundSTPInfo = "True"

                # In case of the Cisco implementation, print the real bridge/root ID, instead of the Cisco ID that includes the VLAN
                originalrootid = rootid
                if RootIDContainsVLAN(self, rootid):
                    originalrootid = GetOriginalRootID(self, rootid)

                originalbridgeid = bridgeid
                if RootIDContainsVLAN(self, bridgeid):
                    originalbridgeid = GetOriginalRootID(self, bridgeid)

                # If multiple instances are used, write the VLAN in the line
                VLANSpacing = ""
                if MultipleInstances:
                    if RootIDContainsVLAN(self, rootid):
                        VLAN = GetRootIDVlan(self, rootid)
                        pre("     VLAN " + str(VLAN) + ": ")
                        VLANSpacing = "     "

                if bridgeid != "":
                    pre("     " + VLANSpacing + "STP Bridge MAC and ID (priority): " + str(bridgemac) + " - " + str(originalbridgeid))
                if rootid != "":
                    pre("     " + VLANSpacing + "STP Root MAC and ID (priority): " + str(rootmac) + " - " + str(originalrootid))
                if version != "":
                    pre("     " + VLANSpacing + "STP Version: " + str(version))
                if age != "":
                    pre("     " + VLANSpacing + "STP Age (distance to STP root): " + str(age))
                if hellotime != "":
                    pre("     " + VLANSpacing + "STP Hello time: " + str(hellotime))
                if fwddelay != "":
                    pre("     " + VLANSpacing + "STP Forward delay: " + str(fwddelay))


            # From here on, IP subnet information starts
            # Get the DHCP information (only the ACK packets)
            dhcp = self.db.executeQuery("select server_id, router, name_server, ntp_server, domain, hostname, netbios_server from dhcp where src_pcap='" + src_pcap + "' and message_type='5';")
            foundDHCPInfo = "" # Reference var, before assignment
             
            if len(dhcp) != 0:
                # Then SMB information has been found
                for record in dhcp:
                    dhcp_serverid = record[0]
                    gateway = record[1]
                    name_server = record[2]
                    ntp_server = record[3]
                    domain = record[4] # Possibly only related to this host
                    hostname = record[5] # Possibly only related to this host
                    netbios_server = record[6]
                    foundDHCPInfo = "True"

            if foundDHCPInfo:
                # Print information, but only if this information has been found
                if dhcp_serverid != "":
                    p("Services in the subnet (obtained through DHCP, therefore this information may differ per client):") 
                    pre("     DHCP server: " + str(dhcp_serverid))
                if gateway != "":
                    pre("     Gateway: " + str(gateway))
                if name_server != "":
                    pre("     Name server: " + name_server)
                if ntp_server != "":
                    pre("     NTP server: " + ntp_server)
                if domain != "":
                    pre("     Domain: " + domain)
                if netbios_server != "":
                    pre("     NetBIOS server: " + netbios_server + " (No NBNS queries will be found, since the clients use a NetBIOS server)")

            # Empty the variables, to prevent from print the same values again in the next loop
            dhcp_serverid = ""
            gateway = ""
            name_server = ""
            ntp_server = ""
            domain = ""
            hostname = ""
            netbios_server = ""


            # L3 IP information
            networks = self.db.executeQuery("SELECT netwid, ip_subnet, subnetguess FROM NETWORK where src_pcap='" + src_pcap + "';")
            for network in networks:
                netwid = network[0]
                ip_subnet = network[1]
                subnetguess = network[2]

                guess = "" # Reference var, before assignment
                if subnetguess: #If the subnet has been guessed, show
                    guess = " (subnet mask was guessed)"

                p(" ")
                p("IP subnet: " + ip_subnet + guess)
                     
                # Get the system ids of the hosts in the selected network
                sysid = self.db.executeQuery("select id, ip, mac from system where system.netwid='" + str(netwid) + "';")

                pre("     Available nodes in the subnet (" + str(len(sysid)) + "):") 
                for system in sysid:
                    ip = system[1]
                    mac = system[2]

                    # Get the information for each system 
                    # Perhaps get hostname?
                    pre("     Node " + ip + " (MAC address: " + mac + "):") 

                    # SMB
                    smb = self.db.executeQuery("select src_name, dst_name, os_major_version, os_minor_version, flags from smb where sysid='" + str(system[0]) + "';")
                    if (len(smb) != 0):
                        # Then SMB information has been found
                        for record in smb:
                            hostname = record[0]
                            workgroup = record[1]
                            dot = "."
                            os = str(record[2]) + dot + str(record[3])
                            flags = record[4]
                        # Writing generic info
                        pre("          Hostname: " + hostname)
                        pre("          Workgroup/domain: " + workgroup)
                        pre("          Windows OS version: " + os)
                        pre("          Roles: " + flags)

                    # NBNS
                        # One may use "unanswered" queries to determine whether a certain service is available
                    nbns = self.db.executeQuery("select query from nbns where sysid='" + str(system[0]) + "';")
                    if (len(nbns) != 0):
                        # Then nbns information has been found
                        pre("          Requests the following names through NetBIOS: ")
                        for record in nbns:
                            query = record[0]
                            pre("                   " + query)
     
                    p(" ")

            # Increase counter for the network
            i = i + 1                     

        go()
