#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *

FORWARDING_TABLE_FILE = 'forwarding_table.txt'
DEFAULT_MAC = "0:0:0:0:0:0"
DEFAULT_NEXT_IP = "0.0.0.0"
DEFAULT_MASK = "255.255.255.255"
BroadCast_MAC="ff:ff:ff:ff:ff:ff"

class FTD:
    def __init__(self,prefix,mask,next_ip,interface_name):
        self.prefix=prefix
        self.mask=mask
        self.next_ip=next_ip
        self.interface_name=interface_name

class RTD:
    def __init__(self,ip,mac,time):
        self.ip=ip
        self.mac=mac
        self.time=time
        self.maxtime=100

def calculate_prefix(ip, mask):
    return IPv4Address(int(ip) & int(mask))

class FD:
    def __init__(self,net):
        self.list=[]
        self.add_netinterfaces(net)
        self.add_bytable()

    def process_interface(self,interface):
        mask = IPv4Address(interface.netmask)
        ip = IPv4Address(interface.ipaddr)
        prefix = calculate_prefix(ip, mask)
        return FTD(prefix, mask, DEFAULT_NEXT_IP, interface.name)

    def add_netinterfaces(self, net):
        for interface in net.interfaces():
            self.list.append(self.process_interface(interface))
            
    def add_bytable(self):
        with open('forwarding_table.txt','r') as fd:
            for line in fd:
                a=line.strip().split()
                ip=IPv4Address(a[0])
                mask=IPv4Address(a[1])
                self.list.append(FTD(IPv4Address(int(ip) & int(mask)), a[1], a[2],a[3]))

    def longest_prefix_match(self,ip):
        int_ip=IPv4Address(ip)
        prefix_length=0
        ans=FTD(IPv4Address("0.0.0.0"),"255.255.255.255","255.255.255.255","1")
        for it in self.list:
            mask= IPv4Address(it.mask)
            if(int(int_ip) & int(mask) == int(it.prefix)):
                log_info(f"{it.prefix}, {it.mask}, {it.next_ip}, {it.interface_name}")
                length=IPv4Network(f"{it.prefix}/{mask}").prefixlen
                if(length > prefix_length):
                    prefix_length=length
                    ans=it
        log_info(f"ip:{ip}, match_ip:{ans.next_ip}, match_prefix:{ans.prefix}, interface_name:{ans.interface_name}")
        return FTD(ans.prefix,ans.mask,ans.next_ip,ans.interface_name)




class RT:
    def __init__(self, net):
        self.net = net
        self.table = []
        self.maxtime = 500
        self.add_bytable()

    def parse_forwarding_table_line(self,line):
        prefix, _, _, interface_name = line.strip().split(maxsplit=3)
        mac = 0
        for inter in self.net.interfaces():
            if(inter.name == interface_name):
                mac=inter.ethaddr
                break
        self.table.append(RTD(prefix,mac,time.time()))

    def add_bytable(self):
        with open(FORWARDING_TABLE_FILE, 'r') as file:
            for line in file:
                self.parse_forwarding_table_line(line)

    def is_in(self,ip):
        for iter in self.table:
            if(int(IPv4Address(ip)) == int(IPv4Address(iter.ip))):
                if(self.maxtime+iter.time<time.time()):
                    return DEFAULT_MAC
                return iter.mac
        return DEFAULT_MAC

    def modify(self, ip, mac, timestamp):
        entry = next((entry for entry in self.table if entry.ip == ip), None)
        if entry:
            entry.mac = mac
            entry.time = timestamp
        else:
            self.table.append(RTD(ip, mac, timestamp))

    def clear_time(self):
        current_time = time.time()
        self.table = [entry for entry in self.table if current_time < self.maxtime+entry.time]

    def show(self):
        for entry in self.table:
            log_info(f"ip: {entry.ip}, mac: {entry.mac}")

class wating_list_element:
    def __init__(self,packet,ftd):
        self.packet=packet
        self.ftd=ftd
        self.chance=5
class time_roundpair:
    def __init__(self,time,rounds,sendrouds):
        self.time=time
        self.rounds=rounds
        self.send_rounds=sendrouds

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self._initialize_components()
        self._initialize_data_structures()
        self.rounds=0

    def _initialize_components(self):
        self.fd = FD(self.net)
        self.rt = RT(self.net)

    def _initialize_data_structures(self):
        self.wl = []
        self.wating_arp = {}

    def send_ARP(self,wle):
        #self.rt.show()
        mac=self.rt.is_in(wle.ftd.next_ip)
        if(mac!=DEFAULT_MAC):
            return
        try:
            interface =self.net.interface_by_name(wle.ftd.interface_name)
        except KeyError:
            return
        packet=create_ip_arp_request(interface.ethaddr,interface.ipaddr,wle.ftd.next_ip)
        self.net.send_packet(interface.name,packet)


    def send_nonARP(self,wle,mac):
        #self.rt.show()
        packet=wle.packet
        eth=packet.get_header(Ethernet)
        try:
            eth.src=self.net.interface_by_name(wle.ftd.interface_name).ethaddr
        except KeyError:
            return
        eth.dst=mac
        ipv4=packet.get_header(IPv4)
        ipv4.ttl=ipv4.ttl-1
        del packet[IPv4]
        del packet[Ethernet]
        packet.insert_header(0,ipv4)
        packet.insert_header(0,eth)
        self.net.send_packet(wle.ftd.interface_name,packet)

    def handle_packet_arp(self,recv):
        time_stamp,interface_name,packet=recv
        arp=packet.get_header(Arp)
        eth=packet.get_header(Ethernet)
        if not arp:
            return
                    
        if(arp.operation==ArpOperation.Reply):
            if(arp.targethwaddr!=eth.dst or arp.senderhwaddr!=eth.src):
                return
            interface=self.net.interface_by_name(interface_name)
            if(eth.dst != interface.ethaddr):
                return
            if(arp.senderhwaddr!=BroadCast_MAC):
                self.rt.modify(arp.senderprotoaddr,arp.senderhwaddr,time.time())
            return

        try:
            interface= self.net.interface_by_ipaddr(arp.targetprotoaddr)
        except KeyError:
            return
        self.rt.modify(arp.senderprotoaddr,arp.senderhwaddr,time.time())

        repacket=create_ip_arp_reply(interface.ethaddr,arp.senderhwaddr,arp.targetprotoaddr,arp.senderprotoaddr)
        self.net.send_packet(interface_name,repacket)


    def _handle_unknown_mac(self,wle,next_ip,new_wl,fixed_time_interval):
                if(wle.ftd.next_ip in self.wating_arp):
                    self._process_pending_arp_request(wle,next_ip,new_wl,fixed_time_interval)
                else:
                    self._initiate_new_arp_request(wle,new_wl)


    def _process_pending_arp_request(self,wle,next_ip,new_wl,fixed_time_interval):
                    pair=self.wating_arp[wle.ftd.next_ip]
                    if(pair.rounds == self.rounds):
                        new_wl.append(wle)
                        return
                    elif(pair.rounds==-1):#no chance
                        return
                    if(time.time()-pair.time>fixed_time_interval):
                        wle.chance-=1
                        if(wle.chance==-1):
                            self.wating_arp[wle.ftd.next_ip]=time_roundpair(time.time(),-1,pair.rounds)
                            return
                        new_wl.append(wle)
                        self.send_ARP(wle)
                        self.wating_arp[wle.ftd.next_ip]=time_roundpair(time.time(),self.rounds,self.rounds)
                    else:
                        self.wating_arp[wle.ftd.next_ip]=time_roundpair(pair.time,self.rounds,pair.send_rounds)
                        new_wl.append(wle)
                        return
    def _initiate_new_arp_request(self,wle,new_wl):
                    if(wle.chance==0):
                        return
                    wle.chance-=1
                    new_wl.append(wle)
                    self.send_ARP(wle)
                    self.wating_arp[wle.ftd.next_ip]=time_roundpair(time.time(),self.rounds,self.rounds)

    def _send_packet_with_known_mac(self,packet, mac_address):
        self.send_nonARP(packet,mac_address)
            
            
    def handle_packet_nonarp(self):
        fixed_time_interval=1
        self.rounds=self.rounds- (-1)
        new_wl=[]

        for wle in self.wl:
            next_ip = wle.ftd.next_ip
            mac_address = self.rt.is_in(next_ip)

            if mac_address == DEFAULT_MAC:
                self._handle_unknown_mac(wle,next_ip,new_wl,fixed_time_interval)
            else:
                self._send_packet_with_known_mac(wle, mac_address)

        for it in self.wating_arp:
            if(self.wating_arp[it].rounds==-1):
                self.wating_arp[it].rounds=0

        self.wl.clear()
        for it in new_wl:
            self.wl.append(it)


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        head=packet.get_header(Ethernet)
        if ((not head) or head.ethertype==EtherType.VLAN) :
            return
        if(head.ethertype!=EtherType.ARP and head.ethertype!=EtherType.IPv4):
            return
        mac=head.dst
        flag=0
        if(mac==BroadCast_MAC):
            flag=1
        if(flag==0):
            for it in self.net.interfaces():
                if(mac==it.ethaddr):
                    flag=1
                    break
        if(flag==0):
            return
        ipx=packet.get_header(IPv4)
        arp=packet.get_header(Arp)
        flag=1

        if not arp:
            ipv4=packet.get_header(IPv4)
            dest_ip=ipv4.dst
            try:
                self.net.interface_by_ipaddr(dest_ip)
            except KeyError:
                if(not(ipv4.ecn==0 or ipv4.protocol==6) or ipv4.total_length<IPv4._MINLEN):
                    return
                ftd=self.fd.longest_prefix_match(dest_ip)
                if(int(ftd.prefix)==0):
                    return
                if(ftd.next_ip==DEFAULT_NEXT_IP):
                    ftd.next_ip=ipv4.dst
                w=wating_list_element(packet,ftd)
                self.wl.append(w)
            return
        self.handle_packet_arp(recv)


        

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        timex=0.1
        while True:
            if(float(time.time()) - timex >0.1):
                self.handle_packet_nonarp()
                timex=float(time.time())
                
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
