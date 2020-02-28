import dpkt
import socket
from pprint import pprint
from struct import *
from datetime import datetime
import sys

def parse_http(buf):
    return buf[:4]

def parse_tcp(buf):
    src_port, dest_port, seq, ack, offset_flags, window = unpack('! H H L L H H', buf[:16])
    offset = (offset_flags >> 12) * 4
    flag_ack = (offset_flags & 16) >> 4
    flag_psh = (offset_flags & 8) >> 3
    flag_syn = (offset_flags & 2) >> 1
    flag_fin = offset_flags & 1
    data = buf[offset:]
    tcp_seg_len = len(data)
    return src_port, dest_port, seq, ack, flag_ack, flag_psh, flag_syn, flag_fin, window, tcp_seg_len, data

def parse_ipv(buf):
    version_header_length = buf[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, dest = unpack('! 8x B B 2x 4s 4s', buf[:20])
    src = '.'.join(map(str, src))
    dest = '.'.join(map(str, dest))
    data = buf[header_length:]
    return proto, src, dest, data
    
def parse_eth(buf):
    data = buf[14:]
    return data
    
def parse_packs(pcap, qn, file_name):
    server_ip = None
    client_ip = None
    no_of_tcp_flows = 0
    syn_set = 0
    total_packets = 0
    start_time = -1
    end_time = -1
    total_bytes = 0
    http_req = []
    http_res = []
    for buf in pcap:
        if qn == 2:
            if start_time == -1:
                start_time = buf[0]
            end_time = buf[0]
        proto, src_ip, dest_ip, ipv_data = parse_ipv(parse_eth(buf[1]))
        src_port, dest_port, seq, ack, flag_ack, flag_psh, flag_syn, flag_fin, window, tcp_seg_len, http_data = parse_tcp(ipv_data)

        if server_ip == None:
            server_ip = dest_ip
            client_ip = src_ip

        if qn == 0 or qn == 1: 
            if proto == 6 and parse_http(http_data) == b'GET ':
                http_req.append(['Request', src_port, dest_port, seq, ack])
            if proto == 6 and parse_http(http_data) == b'HTTP':
                http_res.append(['Response', src_port, dest_port, seq, ack])

        if qn == 1:
            if flag_syn == 1 and src_ip == client_ip:
                syn_set += 1
            if flag_fin == 1 and src_ip == client_ip:
                syn_set -= 1
                if syn_set < 0:
                    print("ERROR: FIN count is greater than SYN")
                else:
                    no_of_tcp_flows += 1

        if qn == 2:
            if src_ip == server_ip:
                total_packets += 1
                total_bytes += sys.getsizeof(buf[1])
            
    if qn == 0:
        print('[Packet Type, Source Port, Dest Port, Seq No, Ack No]')
        for req in http_req:
            print(*req)
            for res in http_res:
                if req[4] == res[3]:
                    print(*res)
            print('')
    if qn == 1:
        if no_of_tcp_flows == 1:
            print(file_name+" uses HTTP 2.0")
        elif no_of_tcp_flows == len(http_req) and len(http_req) != 0:
            print(file_name+" uses HTTP 1.0")
        else:
            print(file_name+" uses HTTP 1.1")
    if qn == 2:
        print("File: "+file_name)
        print(" Total time taken by "+file_name+" is "+str((datetime.fromtimestamp(end_time) - datetime.fromtimestamp(start_time)).total_seconds()))
        print(" Total packets sent from the server: "+str(total_packets))
        print(" Total bytes from the server: "+str(total_bytes))
        
def read_packets(pcap_file_list):
    print('############################################################################')
    print('                            PART C - Q1')
    print('############################################################################')
    with open(pcap_file_list[0], 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        parse_packs(pcap, 0, 'na')
    for i in range(1,3):
        print('############################################################################')
        print('                            PART C - Q'+str(i+1))
        print('############################################################################')
        for file in pcap_file_list:
            with open(file, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                parse_packs(pcap, i, file)
        
if __name__ == '__main__':
    pcap_file_list = sys.argv[1:]
    read_packets(pcap_file_list)
