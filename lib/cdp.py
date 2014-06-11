#!/usr/bin/python

import re
import string


class CDP():

    def __init__(self, logging, db, pcap_name):
        self.logger = logging
        self.db = db
        self.pcap_name = pcap_name

    def process_packet(self, p):

        src_mac = p.src
        ip_addr = ""
        software_version = ""
        port_id = ""
        capabilities = ""
        native_vlan = ""
        voip_vlan = ""
        duplex = ""
        ip_prefix = ""
        power = ""
        device_id = ""
        platform = ""
        power_available = ""

        # Function for processing packets and printing information of CDP Packets

        # Process each field in the packet message
        for f in p[CDPv2_HDR].fields["msg"]:
                # Check if the filed type is a known one
            if f.type in _cdp_tlv_types:
                    # Process each field according to type
                f_type = _cdp_tlv_types[f.type]

                # Make sure we process each address in the message
                if re.match(r"(Addresses|Management Address)", f_type):
                    for ip in f.fields["addr"]:
                        #self.db.writeCDP(p.src, "ip_addr", ip.addr)
                        ip_addr = ip.addr
                elif f_type == "Software Version":
                    #self.db.writeCDP(p.src, "software_version", f.val)
                    software_version = f.val
                elif f_type == "Port ID":
                    #self.db.writeCDP(p.src, "port_id", f.iface)
                    port_id = f.iface
                elif f_type == "Capabilities":
                    # Ugly but works :)
                    #self.db.writeCDP(p.src, "capabilities", "".join(re.findall(r"cap\s*=(\S*)", str(f.show))))
                    capabilities = "".join(re.findall(r"cap\s*=(\S*)", str(f.show)))
                elif f_type == "Native VLAN":
                    #self.db.writeCDP(p.src, "native_vlan", str(f.vlan))
                    native_vlan = str(f.vlan)
                elif f_type == "VoIP VLAN Reply":
                    #self.db.writeCDP(p.src, "voip_vlan", str(f.vlan))
                    voip_vlan = str(f.vlan)
                elif f_type == "Duplex":
                    #self.db.writeCDP(p.src, "duplex", _cdp_duplex[f.duplex])
                    duplex = _cdp_duplex[f.duplex]
                elif f_type == "IP Prefix":
                    #self.db.writeCDP(p.src, "ip_prefix", f.defaultgw)
                    ip_prefix = f.defaultgw
                elif f_type == "Power":
                    #self.db.writeCDP(p.src, "power", f.power)
                    power = f.power
                elif f_type == "Device ID":
                    #self.db.writeCDP(p.src, "device_id", f.val)
                    device_id = f.val
                elif f_type == "Platform":
                    #self.db.writeCDP(p.src, "platform", f.val)
                    platform = f.val
                elif f_type == "Power Available":
                    #self.db.writeCDP(p.src, "power_available", f_type)
                    power_available = f_type

        #print src_mac, ip_addr, software_version, port_id, capabilities, native_vlan, voip_vlan, duplex, ip_prefix, power, device_id, platform, power_available

        self.db.writeCDP(self.pcap_name, src_mac, ip_addr, software_version, port_id, capabilities, native_vlan, voip_vlan, duplex, ip_prefix, power, device_id, platform, power_available)


