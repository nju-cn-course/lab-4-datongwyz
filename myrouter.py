#!/usr/bin/env python3



import time
import switchyard
from switchyard.lib.userlib import *
from enum import Enum
import inspect
from copy import deepcopy

VERBOSE_MODE = False  # 调试模式开关

# 定义数据包状态的枚举类
class PacketState(Enum):
    COMMON = 1         # 普通数据包
    ARP_PACKET = 2     # ARP数据包
    ICMP_PACKET = 3    # ICMP数据包

# 定义重传状态的枚举类
class RetransmissionState(Enum):
    NO_TIMEOUT = 0            # 无超时
    FIRST_TIMEOUT = 1         # 第一次超时
    FINAL_TIMEOUT = 2         # 最终超时
    SEND_ARP_SUCCESS = 3      # 发送ARP成功

# 自定义断言函数，用于条件检查
def check_assertion(condition, message="断言失败"):
    if not condition:
        frame = inspect.currentframe().f_back
        filename = frame.f_code.co_filename
        lineno = frame.f_lineno
        raise AssertionError(f"{message} [文件: {filename}, 行号: {lineno}]")

# 定义用于记录经过时间的类
class ElapsedTime(object):
    def __init__(self):
        self.start_time = time.time()  # 开始时间
        self.elapsed = 0               # 经过时间

    def __str__(self):
        return str.format("(start_time:{}, elapsed:{})", self.start_time, self.elapsed)

# 定义ARP条目的类
class ARPEntry(object):
    def __init__(self, ip_addr, mac_addr, elapsed_time):
        self.ip_addr = ip_addr                # IP地址
        self.mac_addr = mac_addr              # MAC地址
        self.elapsed_time = elapsed_time      # 经过时间对象

    def __str__(self):
        return "ARP条目: IP:{} | MAC:{} | 经过时间:{}".format(
            self.ip_addr, self.mac_addr, self.elapsed_time
        )

    def get_elapsed(self):
        self.elapsed_time.elapsed = time.time() - self.elapsed_time.start_time  # 计算经过时间
        return self.elapsed_time.elapsed

    def reset_timer(self):
        self.elapsed_time.start_time = time.time()  # 重置开始时间
        self.elapsed_time.elapsed = 0               # 重置经过时间

# 定义ARP缓存的类
class ARPCache(object):
    MAX_TIMESTAMP = 100  # 缓存中条目存活的最长时间（秒）

    def __init__(self):
        self.entries = {}  # 用于存储IP-MAC映射的字典

    def add_entry(self, ip_addr, mac_addr):
        check_assertion((mac_addr not in self.entries))  # 确保MAC地址不重复
        elapsed = ElapsedTime()  # 创建一个经过时间对象
        entry = ARPEntry(ip_addr, mac_addr, elapsed)  # 创建ARP条目
        self.entries[ip_addr] = entry  # 添加到缓存中
        log_info(f"****Added {entry} to ARP cache.")  # 记录日志
        self.display_cache()  # 显示当前ARP缓存

    def fetch_mac(self, ip_addr):
        if ip_addr not in self.entries:
            return None  # 如果IP地址不在缓存中，返回None
        check_assertion((ip_addr in self.entries))  # 确保IP地址在缓存中
        return self.entries[ip_addr].mac_addr  # 返回对应的MAC地址

    def update_mac(self, ip_addr, mac_addr):
        if ip_addr not in self.entries:
            return None  # 如果IP地址不在缓存中，返回None
        old_mac = self.entries[ip_addr].mac_addr  # 获取旧的MAC地址
        self.entries[ip_addr].mac_addr = mac_addr  # 更新为新的MAC地址
        log_info(
            f"****Updated MAC for {ip_addr} from {old_mac} to {mac_addr}."
        )  # 记录日志

    def get_time_stamp(self, ip_addr):
        check_assertion((ip_addr in self.entries))  # 确保IP地址在缓存中
        return self.entries[ip_addr].get_elapsed()  # 获取经过时间

    def reset_time(self, ip_addr):
        if ip_addr not in self.entries:
            return None  # 如果IP地址不在缓存中，返回None
        old_time = self.entries[ip_addr].elapsed_time  # 获取旧的时间
        self.entries[ip_addr].reset_timer()  # 重置时间
        log_info(
            f"****Reset time for {ip_addr} from {old_time} to {self.entries[ip_addr].elapsed_time}."
        )  # 记录日志

    def purge_expired_entries(self):
        for key in list(self.entries.keys()):
            current_elapsed = self.entries[key].get_elapsed()  # 获取当前条目的经过时间
            if current_elapsed > self.MAX_TIMESTAMP:
                log_info(
                    f"____Removed expired entry: {self.entries[key]}____"
                )  # 记录日志
                del self.entries[key]  # 删除过期条目

    def display_cache(self):
        print("\nCurrent ARP Cache:")  # 打印当前ARP缓存
        for key in self.entries:
            print(f"{self.entries[key]}")
        print("\n")

# 定义路由条目的类
class RouteEntry:
    def __init__(self, network_prefix, subnet_mask, next_hop, interface):
        self.network_prefix = network_prefix      # 网络前缀
        self.subnet_mask = subnet_mask            # 子网掩码
        self.next_hop = next_hop                  # 下一跳IP地址
        self.interface = interface                # 转发接口

        # 确保参数类型正确
        check_assertion(isinstance(network_prefix, IPv4Address))
        check_assertion(isinstance(subnet_mask, IPv4Address))
        check_assertion(isinstance(next_hop, IPv4Address))
        check_assertion(isinstance(interface, Interface))

    def __str__(self) -> str:
        return f'网络前缀: {self.network_prefix}, 子网掩码: {self.subnet_mask}, 下一跳: {self.next_hop}, 接口: {self.interface.name}'

# 定义路由表的类
class RoutingTable(object):
    def __init__(self, network):
        self.network = network                    # 网络对象
        self.interfaces = network.interfaces()    # 获取所有接口
        self.routes = self.initialize_routes()    # 初始化路由表

        check_assertion(isinstance(self.routes, list))  # 确保路由表是列表

    def initialize_routes(self):
        routing_entries = []  # 初始化路由条目列表

        # 从接口信息添加转发表条目
        for interface in self.interfaces:
            iface_ip = interface.ipaddr       # 接口IP地址
            iface_mask = interface.netmask    # 接口子网掩码

            check_assertion(isinstance(iface_ip, IPv4Address))    # 确保IP地址类型正确
            check_assertion(isinstance(iface_mask, IPv4Address)) # 确保子网掩码类型正确

            prefix = IPv4Address(int(iface_ip) & int(iface_mask))  # 计算网络前缀
            mask = iface_mask
            hop = IPv4Address('0.0.0.0')  # 0.0.0.0 表示直连网络

            route = RouteEntry(prefix, mask, hop, interface)  # 创建路由条目
            routing_entries.append(route)  # 添加到路由条目列表

        # 从 forwarding_table.txt 文件读取并追加转发表条目
        with open('forwarding_table.txt', 'r') as file:
            for line in file:
                values = line.split()  # 按空格分割每行内容
                prefix = IPv4Address(values[0])    # 网络地址
                mask = IPv4Address(values[1])      # 子网掩码
                hop = IPv4Address(values[2])       # 下一跳地址
                iface = self.network.interface_by_name(values[3])  # 接口名称获取接口对象
                file_route = RouteEntry(prefix, mask, hop, iface)   # 创建路由条目
                routing_entries.append(file_route)  # 添加到路由条目列表

        return routing_entries  # 返回完整的路由条目列表

    # 使用最长前缀匹配查找最佳路由条目
    def longest_prefix_match(self, dest_ip):
        check_assertion(isinstance(dest_ip, IPv4Address))  # 确保目标IP地址类型正确
        longest_mask = -1  # 初始化最长子网掩码长度
        best_route = None   # 初始化最佳路由条目

        for route in self.routes:
            route_prefix = route.network_prefix
            route_mask = route.subnet_mask

            # 检查目标IP是否在当前路由条目网络中
            match = ((int(route_mask) & int(dest_ip)) == int(route_prefix))
            if match:
                if int(route_mask) > longest_mask:
                    best_route = route            # 更新最佳路由条目
                    longest_mask = int(route_mask)  # 更新最长子网掩码长度
                else:
                    continue

        debugger() if VERBOSE_MODE else None  # 如果调试模式开启，进入调试
        if best_route is None:
            print(f"未找到适合 {dest_ip} 的路由条目")  # 打印未找到匹配路由的消息
        return best_route  # 返回最佳路由条目

# 定义ARP回复的类
class ARPReply(object):
    def __init__(self, target_ip, target_mac, target_interface, elapsed_time, arp_request_pkt):
        self.target_ip = target_ip                        # 目标IP地址
        self.target_mac = target_mac                      # 目标MAC地址
        self.target_interface = target_interface          # 目标接口
        self.elapsed_time = elapsed_time                  # 经过时间对象
        self.arp_request_pkt = arp_request_pkt            # ARP请求包
        self.packet_queue = []                            # 等待转发的数据包队列
        self.attempts = 1                                 # 重传次数

    def __str__(self):
        return "ARPReply: target_ip:{} | target_mac:{} | elapsed_time:{} | arp_request_pkt:{} \n packet_queue:{}"\
            .format(
                self.target_ip,
                self.target_mac,
                self.elapsed_time,
                self.arp_request_pkt,
                self.packet_queue
            )

    def get_elapsed(self):
        self.elapsed_time.elapsed = time.time() - self.elapsed_time.start_time  # 计算经过时间
        return self.elapsed_time.elapsed

    def should_retransmit(self, timeout=1.0) -> RetransmissionState:
        elapsed = self.get_elapsed()  # 获取经过时间
        assert(self.arp_request_pkt is not None)  # 确保ARP请求包不为空
        assert(self.arp_request_pkt[Arp] is not None)  # 确保ARP包存在

        # 如果目标MAC已知，准备发送数据包
        if self.target_mac is not None:
            return RetransmissionState.SEND_ARP_SUCCESS
        else:
            if (elapsed > timeout) and (self.attempts < 5):
                self.elapsed_time.start_time = time.time()  # 重置开始时间
                self.elapsed_time.elapsed = 0               # 重置经过时间
                print(f"\nAttempt {self.attempts}. Retrying ARP request.")  # 打印重传尝试信息
                return RetransmissionState.FIRST_TIMEOUT
            # 达到第五次尝试，放弃
            elif (elapsed <= timeout) and (self.attempts == 5):
                return RetransmissionState.NO_TIMEOUT
            elif self.attempts >= 5:
                return RetransmissionState.FINAL_TIMEOUT
            else:
                return RetransmissionState.NO_TIMEOUT

# 定义IP路由器的类
class IPRouter(object):
    def __init__(self, network: switchyard.llnetbase.LLNetBase):
        self.network = network                        # 网络对象
        self.my_interfaces = network.interfaces()      # 获取所有接口
        self.arp_cache = ARPCache()                   # 初始化ARP缓存
        self.routing_table = RoutingTable(network)     # 初始化路由表
        self.pending_arp_requests = {}                 # 初始化待处理的ARP请求字典

    def display_table(self):
        for route in self.routing_table.routes:
            print(route)  # 打印每个路由条目

    # 处理ARP包
    def process_arp(self, arp_packet, receiving_interface):
        # 无论如何，在ARP包目标是路由器时，更新ARP缓存
        if arp_packet.operation == ArpOperation.Reply:
            if arp_packet.senderhwaddr == EthAddr('ff:ff:ff:ff:ff:ff'):
                return None  # 如果发送者MAC是广播地址，忽略
            else:
                for interface in self.my_interfaces:
                    # 判断ARP的目标IP是否属于路由器的某个接口
                    if arp_packet.targetprotoaddr == interface.ipaddr:
                        if not self.arp_cache.fetch_mac(arp_packet.senderprotoaddr):
                            self.arp_cache.add_entry(
                                arp_packet.senderprotoaddr, arp_packet.senderhwaddr
                            )
                        else:
                            # 首先更新经过时间
                            self.arp_cache.reset_time(arp_packet.senderprotoaddr)
                            # 检查源MAC是否与缓存中的一致
                            if not (arp_packet.senderhwaddr == self.arp_cache.fetch_mac(arp_packet.senderprotoaddr)):
                                self.arp_cache.update_mac(
                                    arp_packet.senderprotoaddr, arp_packet.senderhwaddr
                                )

        if arp_packet.operation == ArpOperation.Request:
            for interface in self.my_interfaces:
                if arp_packet.targetprotoaddr == interface.ipaddr:
                    if not self.arp_cache.fetch_mac(arp_packet.senderprotoaddr):
                        self.arp_cache.add_entry(
                            arp_packet.senderprotoaddr, arp_packet.senderhwaddr
                        )
                    else:
                        # 首先更新经过时间
                        self.arp_cache.reset_time(arp_packet.senderprotoaddr)
                        # 检查源MAC是否与缓存中的一致
                        if not (arp_packet.senderhwaddr == self.arp_cache.fetch_mac(arp_packet.senderprotoaddr)):
                            self.arp_cache.update_mac(
                                arp_packet.senderprotoaddr, arp_packet.senderhwaddr
                            )

                    # 准备并发送ARP回复
                    reply_pkt = create_ip_arp_reply(
                        interface.ethaddr,
                        arp_packet.senderhwaddr,
                        arp_packet.targetprotoaddr,
                        arp_packet.senderprotoaddr
                    )

                    # 发送ARP回复包
                    self.network.send_packet(receiving_interface, reply_pkt)
                    log_info(f"****Sent ARP reply {reply_pkt} via {receiving_interface.name}.")

        log_info("____No matching interface for ARP packet.____")  # 无匹配接口时记录日志

    # 处理接收到的数据包
    def process_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, iface_name, packet = recv  # 解包收到的数据
        receiving_interface = self.network.interface_by_name(iface_name)  # 获取接收接口对象

        state = None  # 初始化数据包状态

        eth = packet.get_header(Ethernet)  # 获取以太网头

        if eth.ethertype == 0x8100:
            return None  # 如果是802.1Q标签，忽略

        arp_packet = packet.get_header(Arp)  # 获取ARP头
        ipv4_packet = packet.get_header(IPv4)  # 获取IPv4头
        destination_ip = None  # 初始化目标IP

        check_assertion(eth is not None)  # 确保以太网头存在

        if arp_packet is None:
            log_info("____Received a non-ARP packet.____")  # 记录收到非ARP包
            check_assertion(ipv4_packet is not None)  # 确保IPv4头存在
            state = PacketState.COMMON  # 设置状态为普通数据包
            destination_ip = ipv4_packet.dst  # 获取目标IP
        else:
            check_assertion(ipv4_packet is None)  # 确保没有IPv4头
            destination_ip = arp_packet.targetprotoaddr  # 获取ARP目标IP
            state = PacketState.ARP_PACKET  # 设置状态为ARP数据包

        # 如果以太网目标既不是广播地址，也不是接收接口的MAC地址，则丢弃数据包
        if (eth.dst != EthAddr('ff:ff:ff:ff:ff:ff')) and (eth.dst != receiving_interface.ethaddr):
            return None

        # 使用最长前缀匹配查找路由条目
        route_entry = self.routing_table.longest_prefix_match(destination_ip)
        if route_entry is None:
            return None  # 如果没有匹配，丢弃数据包

        print(f"\n{packet} 路由条目: {route_entry}\n")  # 打印匹配的路由条目

        # 如果数据包是发往路由器本身，丢弃数据包
        if state is not PacketState.ARP_PACKET:
            for interface in self.my_interfaces:
                if interface.ipaddr == destination_ip:
                    print("Dropping packet destined for router.")  # 打印丢弃信息
                    return None

        if state == PacketState.ARP_PACKET:
            check_assertion(isinstance(arp_packet, Arp), f"isinstance({arp_packet}, Arp)")
            self.process_arp(arp_packet, receiving_interface)  # 处理ARP包

        elif state == PacketState.COMMON:
            if route_entry.next_hop == IPv4Address('0.0.0.0'):
                next_ip = destination_ip  # 直连网络，下一跳为目标IP
            else:
                next_ip = route_entry.next_hop  # 否则，使用路由条目的下一跳

            next_mac = self.arp_cache.fetch_mac(next_ip)  # 获取下一跳的MAC地址
            next_interface = route_entry.interface  # 获取转发接口
            arp_request_pkt = None  # 初始化ARP请求包

            # 如果下一跳MAC未知，发送ARP请求
            if next_mac is None:
                arp_request_pkt = create_ip_arp_request(
                    next_interface.ethaddr, next_interface.ipaddr, next_ip
                )

                # 如果尚未发送ARP请求，则发送
                if str(next_ip) not in self.pending_arp_requests:
                    self.network.send_packet(next_interface, arp_request_pkt)

            # 深拷贝数据包用于转发
            forwarded_packet = deepcopy(packet)

            print(f"{next_ip} detected. Forwarding packet: {forwarded_packet}")  # 打印转发信息
            forwarded_packet[Ethernet].src = next_interface.ethaddr  # 设置源MAC地址
            forwarded_packet[Ethernet].dst = next_mac              # 设置目标MAC地址
            forwarded_packet[IPv4].ttl -= 1                         # 减少TTL

            if next_mac is not None:
                self.network.send_packet(next_interface, forwarded_packet)  # 发送转发的数据包
                return None

            check_assertion(next_mac is None)  # 确保下一跳MAC地址为空

            # 将数据包加入等待ARP解析的队列
            if str(next_ip) not in self.pending_arp_requests:
                arp_reply = ARPReply(
                    next_ip,
                    next_mac,
                    next_interface,
                    ElapsedTime(),
                    arp_request_pkt
                )
                arp_reply.packet_queue.append(forwarded_packet)  # 添加到数据包队列
                self.pending_arp_requests[str(next_ip)] = arp_reply  # 添加到待处理ARP请求
            else:
                self.pending_arp_requests[str(next_ip)].packet_queue.append(forwarded_packet)

    # 处理ARP请求队列
    def process_arp_queue(self):
        if not self.pending_arp_requests:
            return None  # 如果没有待处理ARP请求，返回

        for target_ip, arp_reply in list(self.pending_arp_requests.items()):
            assert(isinstance(arp_reply, ARPReply))  # 确保对象类型正确
            assert(target_ip == str(arp_reply.target_ip))  # 确保IP地址匹配

            # 从ARP缓存中获取目标IP的MAC地址
            arp_reply.target_mac = self.arp_cache.fetch_mac(arp_reply.target_ip)
            for pkt in arp_reply.packet_queue:
                pkt[Ethernet].dst = arp_reply.target_mac  # 更新数据包的目标MAC地址

            retransmission_decision = arp_reply.should_retransmit()  # 判断是否需要重传

            if retransmission_decision is RetransmissionState.SEND_ARP_SUCCESS:
                for pkt in arp_reply.packet_queue:
                    print(f"LOG: Forwarding packet: {pkt}")  # 打印转发日志
                for pkt in arp_reply.packet_queue:
                    self.network.send_packet(arp_reply.target_interface, pkt)  # 发送数据包
                print(f"DELETE: Removing ARP reply for {arp_reply}\n")  # 打印删除信息
                del self.pending_arp_requests[target_ip]  # 从待处理队列中删除

            elif retransmission_decision is RetransmissionState.NO_TIMEOUT:
                assert(arp_reply.target_mac is None)
                continue  # 不做任何处理

            elif retransmission_decision is RetransmissionState.FIRST_TIMEOUT:
                assert(arp_reply.target_mac is None)
                arp_reply.attempts += 1  # 增加重传次数
                self.network.send_packet(arp_reply.target_interface, arp_reply.arp_request_pkt)  # 重新发送ARP请求

            elif retransmission_decision is RetransmissionState.FINAL_TIMEOUT:
                assert(arp_reply.target_mac is None)
                assert(arp_reply.attempts >= 5)
                print(f"DELETE: Removing ARP reply after final timeout: {arp_reply}\n")  # 打印删除信息
                del self.pending_arp_requests[target_ip]  # 从待处理队列中删除

            else:
                check_assertion(False)  # 其他情况，触发断言错误

  
    def start(self):
        log_info(f"****Router interfaces: {self.network.interfaces()}")  
        self.display_table()  

        while True:
            self.process_arp_queue()  

            try:
                received = self.network.recv_packet(timeout=1.0)  
            except NoPackets:
                continue  
            except Shutdown:
                break  

            self.arp_cache.purge_expired_entries()  
            self.process_packet(received)  

        self.shutdown_router()  

    
    def shutdown_router(self):
        self.network.shutdown()  


def main(network):
    router = IPRouter(network)  
    router.start()  