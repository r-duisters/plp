import sqlite3 as sqlite
import os
import re
import types
from netaddr import *
from types import *

class DB():
    """

    """

    def __init__(self, logger, sqliteFile):
        ""
        self.logger = logger
        self.sqliteFile = sqliteFile
        self.sqLiteConnect(sqliteFile, self.checkIfDBExists())

    def checkIfDBExists(self):
        if os.path.exists(self.sqliteFile):
            DbExists = "True"
            return DbExists
        else:
            DbExists = "False"
            return DbExists


    def sqLiteConnect(self, db, DbExists):
        if DbExists == "True":
            # On disk database
            self.con = sqlite.connect(db) 
            self.cur = self.con.cursor()
            self.logger.info("Database " + db + " exists, adding records to the existing database")
        else:
            # In memory database, that will later be dumped to file (for performance reasons)
            self.con = sqlite.connect(':memory:') 
            self.cur = self.con.cursor()
            self.createSqliteTables()
            self.logger.info("Database " + db + " does not exist, creating a new database")

    def sqLiteDumpMemDB(self):
        # First, checking whether the DB already exists (and whether it should be dumped to file)
        if self.checkIfDBExists() != "True":
            # Dumping the database to a sqlite file..
            full_dump = os.linesep.join(self.con.iterdump())
            #myfile = file("schema.sql", 'w')
            #print >> myfile, full_dump
            #myfile.close()
            self.dumpdb_con = sqlite.connect(self.sqliteFile)
            self.dumpdb_cur = self.dumpdb_con.cursor()
            self.dumpdb_cur.executescript(full_dump)

    def createSqliteTables(self):
        # Getting the configured tables
        self.cur.execute('select * from sqlite_master') 
        tableresults = self.cur.fetchall()

        if (len(tableresults)==0):
            # Then we need to build the tables
            self.cur.execute('CREATE TABLE system (id integer primary key autoincrement unique,\
netwid integer references network(netwid), src_pcap string, mac string, ip string);')
            self.cur.execute('CREATE TABLE network (netwid integer primary key autoincrement,\
ip_subnet string, subnetguess string, l2_vlan string, src_pcap string);')
            self.cur.execute('CREATE TABLE CDP (id integer primary key autoincrement unique,\
 sysid integer references system(id), src_pcap string, src_mac string unique, device_id string, duplex string, platform string, \
ip_addr string, software_version string, port_id string, capabilities string, \
native_vlan string, voip_vlan string, ip_prefix string, power string, power_available string);')
            self.cur.execute('CREATE TABLE NBNS (id integer primary key autoincrement unique, \
sysid integer references system(id), src_pcap string, src_mac string, src_ip string, dst_ip string, query string);')
            self.cur.execute('CREATE TABLE DHCP (id integer primary key autoincrement unique, \
sysid integer references system(id), src_pcap string, src_mac string, dst_mac string,  src_ip string, dst_ip string, message_type string, \
lease_time string, server_id string, subnet_mask string, router string, name_server string, \
ntp_server string, domain string, hostname string, netbios_server string);')
            self.cur.execute('CREATE TABLE STP (id integer primary key autoincrement unique, \
sysid integer references system(id), src_pcap string, src_mac string, version string, bpdutype string, rootid string, rootmac string, \
pathcost string, bridgeid string, bridgemac string, portid string, age string, maxage string, \
hellotime string, fwddelay string);')
            self.cur.execute('CREATE TABLE SMB (id integer primary key autoincrement unique, \
sysid integer references system(id), src_pcap string, src_mac string, src_ip string, src_name string, dst_name string, \
os_major_version string, os_minor_version string, flags string);')
        else:
            self.logger.info("The output database is not empty. No need to create tables")

    def getSysID(self, src_mac, ip):
        self.cur.execute("SELECT id FROM system WHERE src_mac='" + src_mac + "' AND ip='" + ip + ";")
        res = self.cur.fetchall()
        if len(res) == 0:
            return False
        else:
            return res

    def addSysID(self, src_mac, ip):
        sqlquery = "INSERT INTO system(src_mac, ip) VALUES ('" + src_mac + "','" + ip + "');"
        self.cur.execute(sqlquery)
        self.con.commit()

    def writeCDP(self, src_pcap, src_mac, ip_addr, software_version, port_id, capabilities, native_vlan, voip_vlan, duplex, ip_prefix, power, device_id, platform, power_available):
        #Checking if the CDP entry has been fully processed before (for performance reasons)
        sqlquery = "SELECT id FROM CDP WHERE \
src_mac='" + src_mac + "' \
AND ip_addr='" + ip_addr + "' \
AND software_version='" + software_version + "' \
AND port_id='" + port_id + "' \
AND capabilities='" + capabilities + "' \
AND native_vlan='" + native_vlan + "' \
AND voip_vlan='" + voip_vlan + "' \
AND duplex='" + duplex + "' \
AND ip_prefix='" + ip_prefix + "' \
AND power='" + power + "' \
AND device_id='" + device_id + "' \
AND platform='" + platform + "' \
AND power_available='" + power_available + "';"

        self.cur.execute(sqlquery)
        res = self.cur.fetchall()

        # If the record doesn't exist, add it
        if (len(res) == 0) : 
            sqlquery = "INSERT INTO CDP(src_pcap, src_mac, ip_addr, software_version, \
port_id, capabilities, native_vlan, voip_vlan, duplex, ip_prefix, power, \
device_id, platform, power_available) values ('\
" + src_pcap + "','\
" + src_mac + "','\
" + ip_addr + "','\
" + software_version + "','\
" + port_id + "','\
" + capabilities + "','\
" + native_vlan + "','\
" + voip_vlan + "','\
" + duplex + "','\
" + ip_prefix + "','\
" + power + "','\
" + device_id + "','\
" + platform + "','\
" + power_available + "');"

            self.cur.execute(sqlquery)
            self.con.commit()
            self.logger.debug("Adding CDP entry for " + src_mac + " - " + device_id )

    def writeNBNS(self, src_pcap, src_mac, src_ip, dst_ip, query):
        # Checking if the NBNS entry has been added before (for performance reasons)
        sqlquery = "SELECT id FROM NBNS WHERE \
src_mac='" + src_mac + "\
' AND src_ip='" + src_ip + "\
' AND dst_ip='" + dst_ip + "\
' AND query='" + query + "';"

        self.cur.execute(sqlquery)
        res = self.cur.fetchall()

        # If the record doesn't exist, add it
        if (len(res) == 0) : 
            sqlquery = "INSERT INTO NBNS(src_pcap, src_mac,src_ip,dst_ip,query) values ('" + src_pcap + "','" + src_mac + "','" + src_ip  + "','" + dst_ip + "','" + query + "');"
            self.cur.execute(sqlquery)
            self.con.commit()
            self.logger.debug("Adding NBNS entry for " + src_ip + " - " + query )

    def writeDHCP(self, src_pcap, src_mac, dst_mac, src_ip, dst_ip, message_type, lease_time, server_id, subnet_mask, router, name_server, ntp_server, domain, hostname, netbios_server):
        if domain != "":
            # Domain sanitization
            domain = re.sub(r'[^\x20-\x7e]', '', domain)

        # Checking if the DHCP entry has been added before (for performance reasons)
        sqlquery = "SELECT id FROM DHCP WHERE \
src_mac='" + src_mac + "\
' AND dst_mac='" + dst_mac + "\
' AND src_ip='" + src_ip + "\
' AND dst_ip='" + dst_ip + "\
' AND message_type='" + message_type + "\
' AND lease_time='" + lease_time + "\
' AND server_id='" + server_id + "\
' AND subnet_mask='" + subnet_mask + "\
' AND router='" + router + "\
' AND name_server='" + name_server + "\
' AND ntp_server='" + ntp_server + "\
' AND domain='" + domain + "\
' AND hostname='" + hostname + "\
' AND netbios_server='" + netbios_server + "';"

        self.cur.execute(sqlquery)
        res = self.cur.fetchall()

        # If the record doesn't exist, add it
        if (len(res) == 0) : 
            sqlquery = "INSERT INTO DHCP(src_pcap, src_mac, dst_mac, src_ip, dst_ip, \
message_type, lease_time, server_id, subnet_mask, router, name_server, \
ntp_server, domain, hostname, netbios_server) values ('\
" + src_pcap + "','\
" + src_mac + "','\
" + dst_mac + "','\
" + src_ip + "','\
" + dst_ip + "','\
" + message_type + "','\
" + lease_time + "','\
" + server_id + "','\
" + subnet_mask + "','\
" + router + "','\
" + name_server + "','\
" + ntp_server + "','\
" + domain + "','\
" + hostname + "','\
" + netbios_server + "');"

            self.cur.execute(sqlquery)
            self.con.commit()

            if message_type == "8":
                self.logger.debug("Adding DHCP inform entry for " + hostname )
            elif message_type == "5":
                self.logger.debug("Adding DHCP ack entry for " + dst_ip )

    def writeSTP(self, src_pcap, src_mac, version, bpdutype, rootid, rootmac, pathcost, bridgeid, bridgemac, portid, age, maxage, hellotime, fwddelay):
        # Checking if the STP entry has been added before (for performance reasons)
        sqlquery = "SELECT id FROM STP WHERE \
src_mac='" + src_mac + "\
' AND version='" + version + "\
' AND bpdutype='" + bpdutype + "\
' AND rootid='" + rootid + "\
' AND rootmac='" + rootmac + "\
' AND pathcost='" + pathcost + "\
' AND bridgeid='" + bridgeid + "\
' AND bridgemac='" + bridgemac + "\
' AND portid='" + portid + "\
' AND age='" + age + "\
' AND maxage='" + maxage + "\
' AND hellotime='" + hellotime + "\
' AND fwddelay='" + fwddelay + "';"

        self.cur.execute(sqlquery)
        res = self.cur.fetchall()

        # If the record doesn't exist, add it
        if (len(res) == 0) : 
            sqlquery = "INSERT INTO STP(src_pcap, src_mac, version, bpdutype, rootid, rootmac, pathcost, bridgeid, bridgemac, portid, age, maxage, hellotime, fwddelay) values ('\
" + src_pcap + "','\
" + src_mac + "','\
" + version + "','\
" + bpdutype + "','\
" + rootid + "','\
" + rootmac + "','\
" + pathcost + "','\
" + bridgeid + "','\
" + bridgemac + "','\
" + portid + "','\
" + age + "','\
" + maxage + "','\
" + hellotime + "','\
" + fwddelay + "' );"

            self.cur.execute(sqlquery)
            self.con.commit()

            self.logger.debug("Adding STP entry for " + src_mac )


    def writeSMB(self, src_pcap, src_mac, src_ip, src_name, dst_name, os_major_version, os_minor_version, flags):
        # Checking if the SMB entry has been added before (for performance reasons)
        sqlquery = "SELECT id FROM SMB WHERE \
src_mac='" + src_mac + "\
' AND src_ip='" + src_ip + "\
' AND src_name='" + src_name + "\
' AND dst_name='" + dst_name + "\
' AND os_major_version='" + os_major_version + "\
' AND os_minor_version='" + os_minor_version + "\
' AND flags='" + flags + "';"

        self.cur.execute(sqlquery)
        res = self.cur.fetchall()

        # If the record doesn't exist, add it
        if (len(res) == 0) : 
            sqlquery = "INSERT INTO SMB(src_pcap, src_mac, src_ip, src_name, dst_name, os_major_version, os_minor_version, flags) values ('\
" + src_pcap + "','\
" + src_mac + "','\
" + src_ip + "','\
" + src_name + "','\
" + dst_name + "','\
" + os_major_version + "','\
" + os_minor_version + "','\
" + flags + "' );"

            self.cur.execute(sqlquery)
            self.con.commit()

            self.logger.debug("Adding SMB entry for " + src_name )

    def createRelations(self):

        def DHCP(self):
            # The "interesting" DHCP packet types are put into an array, to scan for them, since they require a different treatment
            message_type = []
            message_type.append("5") # DHCP ACK
            message_type.append("8") # DHCP Inform

            for type in message_type:
                if type == "5":
                    # DHCP Ack is sent from DHCP server to client. The source mac is either from the DHCP server or a relay.
                    # The dst_mac is from the client
                    sqlquery = "SELECT dst_mac,dst_ip,src_pcap FROM DHCP WHERE message_type='5';"
                elif type == "8":
                    # DHCP Inform is sent from the client, to the DHCP server. The source mac is either from the DHCP server or a relay.
                    # The dst_mac is from the client
                    sqlquery = "SELECT src_mac,src_ip,src_pcap FROM DHCP WHERE message_type='8';"
                self.cur.execute(sqlquery)
                res = self.cur.fetchall()

                for i in res:
                    mac = i[0]
                    ip = i[1]
                    src_pcap = i[2]
                    allow_ip_update = "True"

                    # Only if it is not send to a broadcast address (doesn't make sense to add a device for a broadcast address)
                    if mac != "ff:ff:ff:ff:ff:ff":
                        AddSystem(self, mac, ip, allow_ip_update, src_pcap)
                        systemid = GetSystemID(self, mac, ip)

                        # Add the system ID to the DHCP table
                        if type == "5":
                            add_sys_id = "UPDATE DHCP SET sysid=" + systemid + " WHERE dst_mac='" + mac + "' AND dst_ip='" + ip + "' AND src_pcap='" + src_pcap +"' ;"
                        if type == "8":
                            add_sys_id = "UPDATE DHCP SET sysid=" + systemid + " WHERE src_mac='" + mac + "' AND src_ip='" + ip + "' AND src_pcap='" + src_pcap +"' ;"
                        self.cur.execute(add_sys_id)
                        self.con.commit()

        def STP(self):
                sqlquery = "SELECT src_mac, src_pcap FROM STP;"
                self.cur.execute(sqlquery)
                res = self.cur.fetchall()

                for i in res:
                    mac = i[0]
                    src_pcap = i[1]

                    # Only if it is not send to a broadcast address (doesn't make sense to add a device for a broadcast address)
                    if mac != "ff:ff:ff:ff:ff:ff":
                        sqlquery = "SELECT id FROM SYSTEM WHERE mac='" + mac + "' AND src_pcap='" + src_pcap + "' ;"
                        self.cur.execute(sqlquery)
                        result = self.cur.fetchall()

                        # If the record doesn't exist in the system table, add it
                        if (len(result) == 0) : 
                            sqlquery = "INSERT INTO SYSTEM(mac, src_pcap) values ('" + mac + "','" + src_pcap + "');"
                            self.cur.execute(sqlquery)
                            self.con.commit()
                            self.logger.debug("Adding system ID for " + mac )

                            # Do the query again, after adding the system id
                            sqlquery = "SELECT id FROM SYSTEM WHERE mac='" + mac + "' AND src_pcap='" + src_pcap + "' ;"
                            self.cur.execute(sqlquery)
                            result = self.cur.fetchall()

                        # Add the system ID to the STP table
                        add_sys_id = "UPDATE STP SET sysid=" + str(result[0]).strip('(),"') + " WHERE src_mac='" + mac + "' AND src_pcap='" + src_pcap +"' ;"
                        self.cur.execute(add_sys_id)
                        self.con.commit()

        def CDP(self):
                sqlquery = "SELECT src_mac, src_pcap FROM CDP;"
                self.cur.execute(sqlquery)
                res = self.cur.fetchall()

                for i in res:
                    mac = i[0]
                    src_pcap = i[1]

                    sqlquery = "SELECT id FROM SYSTEM WHERE mac='" + mac + "';"
                    self.cur.execute(sqlquery)
                    result = self.cur.fetchall()

                    # If the record doesn't exist in the system table, add it
                    if (len(result) == 0) : 
                        sqlquery = "INSERT INTO SYSTEM(mac, src_pcap) values ('" + mac + "','" + src_pcap + "');"
                        self.cur.execute(sqlquery)
                        self.con.commit()
                        self.logger.debug("Adding system ID for " + mac )

                        # Do the query again, after adding the system id
                        sqlquery = "SELECT id FROM SYSTEM WHERE mac='" + mac + "' AND src_pcap='" + src_pcap + "' ;"
                        self.cur.execute(sqlquery)
                        result = self.cur.fetchall()

                        # Add the system ID to the STP table
                    add_sys_id = "UPDATE CDP SET sysid=" + str(result[0]).strip('(),"') + " WHERE src_mac='" + mac + "' AND src_pcap='" + src_pcap +"' ;"
                    self.cur.execute(add_sys_id)
                    self.con.commit()

        def NBNS(self):
                sqlquery = "SELECT src_mac,src_ip,src_pcap FROM NBNS;"
                self.cur.execute(sqlquery)
                res = self.cur.fetchall()

                for i in res:
                    mac = i[0]
                    ip = i[1]
                    src_pcap = i[2]
                    allow_ip_update = "True"

                    AddSystem(self, mac, ip, allow_ip_update, src_pcap)
                    systemid = GetSystemID(self, mac, ip)

                    # Add the system ID to the NBNS table
                    add_sys_id = "UPDATE NBNS SET sysid=" + systemid + " WHERE src_mac='" + mac + "' AND src_ip='" + ip + "' ;"
                    self.cur.execute(add_sys_id)
                    self.con.commit()

        def SMB(self):
                sqlquery = "SELECT src_mac,src_ip,src_pcap FROM SMB;"
                self.cur.execute(sqlquery)
                res = self.cur.fetchall()

                for i in res:
                    mac = i[0]
                    ip = i[1]
                    src_pcap = i[2]
                    allow_ip_update = "True"

                    AddSystem(self, mac, ip, allow_ip_update, src_pcap)
                    systemid = GetSystemID(self, mac, ip)

                    # Add the system ID to the SMB table
                    add_sys_id = "UPDATE SMB SET sysid=" + systemid + " WHERE src_mac='" + mac + "' AND src_ip='" + ip + "' ;"
                    self.cur.execute(add_sys_id)
                    self.con.commit()

        def AddSystem(self, mac, ip, allow_ip_update, src_pcap):
            # This procedure adds a system to the system table
            if allow_ip_update: 
                # This value checks whether the protocol is allowed to update the IP field
                sqlquery = "SELECT id FROM SYSTEM WHERE mac='" + mac + "';"
            else:
                sqlquery = "SELECT id FROM SYSTEM WHERE mac='" + mac + "' AND ip='" + ip + "' ;"
            self.cur.execute(sqlquery)
            result = self.cur.fetchall()

            # If the record doesn't exist in the system table, add it
            if (len(result) == 0) : 
                sqlquery = "INSERT INTO SYSTEM(mac, ip, src_pcap) values ('" + mac + "','" + ip + "','" + src_pcap + "' );"
                self.cur.execute(sqlquery)
                self.con.commit()
                self.logger.debug("Adding system ID for " + mac + " - " + ip )
            else:
                # The record exists. A field may need to be added (such as the IP address)
                if allow_ip_update: 
                    sqlquery = "UPDATE SYSTEM SET ip ='" + ip + "' WHERE mac='" + mac + "' ;"
                    self.cur.execute(sqlquery)
                    self.con.commit()

        def GetSystemID(self, mac, ip):
            sqlquery = "SELECT id FROM SYSTEM WHERE mac='" + mac + "' AND ip='" + ip + "' ;"
            self.cur.execute(sqlquery)
            result = self.cur.fetchall()
            return str(result[0]).strip('(),"')

        def AddNetworksDHCP(self):
            # Adding a network, by making use of DHCP first (DHCP displays the subnet)
            # Only the DHCP Ack records have a subnet
            sqlquery = "SELECT dst_ip,subnet_mask,src_pcap FROM DHCP WHERE message_type='5';"
            self.cur.execute(sqlquery)
            result = self.cur.fetchall()

            # Enumerating the records
            for netw in result:
                # Combine the records for input in the GetNetw procedure
                ip = str(netw[0]).strip('(),"')
                subnet = str(netw[1]).strip('(),"')
                IPandSubnet = ip + "/" + subnet
                NetwAddr = GetNetwAddr(self, IPandSubnet)
                src_pcap =  str(netw[2]).strip('(),"')

                sqlquery = "SELECT netwid FROM NETWORK WHERE ip_subnet='" + str(NetwAddr) + "' AND src_pcap='" + src_pcap +"' ;"
                self.cur.execute(sqlquery)
                result = self.cur.fetchall()

                # If the record doesn't exist in the network table, add it
                if (netw[0] != "255.255.255.255") and (len(result) == 0):
                    sqlquery = "INSERT INTO network(ip_subnet, src_pcap) values ('" + str(NetwAddr) + "','" + src_pcap + "' );"
                    self.cur.execute(sqlquery)
                    self.con.commit()
                    self.logger.debug("Adding network " + str(NetwAddr) )

        def AddSystemstoNetwork(self):
            sqlquery = "SELECT ip, src_pcap FROM system;"
            self.cur.execute(sqlquery)
            result = self.cur.fetchall()

            # Enumerating the records
            for address in result:
                ipaddr = address[0]
                src_pcap = address[1]

                if (type(ipaddr) is not NoneType):
                # In some cases, the IP address may be empty. If it's not, continue
                    sqlquery = "SELECT ip_subnet FROM NETWORK;"
                    self.cur.execute(sqlquery)
                    subnets = self.cur.fetchall()

                    exists = "False"
                    # When no subnet has been found, a generic /24 subnet will be guessed
                    # If the subnet has been guessed, the subnetguess flag will be set to "True"
                    if (len(subnets) == 0) : 
                        # No networks exist in the DB, let's add!
                        exists = "False"
                    else: 
                        # Networks are found, let's check if others need to be added
                        for subnet in subnets:
                            networkaddr = str(subnet).strip('(),\'u"')
                            #print ipaddr, networkaddr
                            # For each subnet, check whether the address belongs to it 
                            if addressInNetwork(ipaddr, networkaddr):
                                # If the address belongs to the network, the "Exists" flag will be set
                                exists = "True"
                            #print ipaddr, networkaddr

                    if exists == "False":
                        # Then the network should be added
                            # You can also get the subnet from NBNS!
                        ip = ipaddr
                        subnet = "24" # The default /24 will be used
                        IPandSubnet = str(ip) + "/" + str(subnet)
                        NetwAddr = GetNetwAddr(self, IPandSubnet)
                        # The subnetguess flag will be set to true, since it is a guess
                        sqlquery = "INSERT INTO network(ip_subnet, subnetguess, src_pcap) values ('" + str(NetwAddr) + "', 'True','" + src_pcap + "' );"
                        self.cur.execute(sqlquery)
                        self.con.commit()
                        self.logger.debug("Adding network " + str(NetwAddr) + " (subnet guess)" )

                    # Now the host can be added to the network
                    # First, enumerate the ip_subnets again (to check if the host belongs to one)
                    sqlquery = "SELECT netwid, ip_subnet FROM NETWORK;"
                    self.cur.execute(sqlquery)
                    subnets = self.cur.fetchall()
                    # For each subnet, check whether the address belongs to it 
                    for subnet in subnets:
                        networkaddr = str(subnet[1]).strip('(),\'u"')
                        
                        if addressInNetwork(ipaddr, networkaddr):
                            # So, the host belongs to the network
                            netwid = str(subnet[0])
                            #print ipaddr, networkaddr, netwid
                            # If the relation doesn't exist in the DB, create it
                            sqlquery = "SELECT netwid FROM SYSTEM WHERE ip='" + ipaddr + "' ;"
                            self.cur.execute(sqlquery)
                            result = self.cur.fetchall()

                            # If the record doesn't exist in the network table, add it
                            if (len(result) == 0) or (str(result) == "[(None,)]"):
                                sqlquery = "UPDATE SYSTEM SET netwid=" + netwid + " WHERE ip='" + ipaddr + "';"
                                self.cur.execute(sqlquery)
                                self.con.commit()
                                self.logger.debug("Adding system " + ipaddr  + " to network " + netwid)

        def GetNetwAddr(self, netw):
            ip = IPNetwork(netw)
            total = str(ip.network) + "/" + str(ip.prefixlen)
            return total

        def addressInNetwork(ip, net):
            import socket,struct
            ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
            netstr, bits = net.split('/')
            netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
            mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
            return (ipaddr & mask) == (netaddr & mask)


        # And perhaps a module that does this would be nice
        DHCP(self)
        STP(self)
        CDP(self)
        NBNS(self)
        SMB(self)

        AddNetworksDHCP(self) 
        AddSystemstoNetwork(self)

    def executeQuery(self, query):
        self.cur.execute(query)
        result = self.cur.fetchall()
        return result
        




