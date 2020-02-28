import dpkt
import socket
from pprint import pprint
from struct import *
from datetime import datetime
import sys

def parse_tcp(buf):
    src_port, dest_port, seq, ack, offset_flags, window = unpack('! H H L L H H', buf[:16])
    offset = (offset_flags >> 12) * 4
    flag_ack = (offset_flags & 16) >> 4
    flag_psh = (offset_flags & 8) >> 3
    flag_syn = (offset_flags & 2) >> 1
    flag_fin = offset_flags & 1
    data = buf[offset:]
    tcp_seg_len = len(data)
    return src_port, dest_port, seq, ack, flag_ack, flag_psh, flag_syn, flag_fin, window, tcp_seg_len

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

class Qn2_var:
    def __init__(self, seq):
        self.seq = seq     
    def add_ack(self, ack):
        self.ack = ack
    def add_window(self, window):
        self.window = window
        
class Qn2:
    def __init__(self, psh):
        self.psh = psh
        self.next_psh = -1
        self.next_psh_ack = -1
    
def parse_packs(pcap):
    server_ip = None
    client_ip = None
    server_ports = []
    no_of_tcp_flows = 0
    syn_set = 0
    Qn2List = []
    repeat_seq_count = [0, 0, 0]
    fast_retrans = [0, 0, 0]
    total_packets = [0, 0, 0]
    total_ack_packets = [0, 0, 0]
    prev_ack_size = [-1, -1, -1]
    seq_set = [set(), set(), set()]
    ack_set = [set(), set(), set()]
    ack_dest = [{},{},{}]
    start_time = [-1, -1, -1]
    final_seq = [-1, -1, -1]
    end_time = [-1, -1, -1]
    total_time = [-1, -1, -1]
    total_bytes = [0, 0, 0]
    total_bytes_recv = [0, 0, 0]
    start_seq = [-1, -1, -1]
    start_seq_recv = [-1, -1, -1]
    cong_win = [0, 0, 0]
    cong_win_free = [0, 0, 0]
    last10cong = [[] for i in range(3)]
    psh_rec = [[] for i in range(3)]
    psh_ack_rec = [[] for i in range(3)]
    psh_next_rec = [[] for i in range(3)]
    psh_next_ack_rec = [[] for i in range(3)]
    line_count = 0
    for buf in pcap:
        line_count+=1
        proto, src_ip, dest_ip, ipv_data = parse_ipv(parse_eth(buf[1]))
        src_port, dest_port, seq, ack, flag_ack, flag_psh, flag_syn, flag_fin, window, tcp_seg_len = parse_tcp(ipv_data)

        if server_ip == None:
            if src_port == 80:
                server_ip = dest_ip
                client_ip = src_ip
            else:
                server_ip = src_ip
                client_ip = dest_ip

        if src_ip == server_ip:
            if src_port not in server_ports:
                server_ports.append(src_port)
                
        if dest_ip == server_ip:
            if dest_port not in server_ports:
                server_ports.append(dest_port)
# Qn 1 start
        if flag_syn == 1 and src_ip == server_ip:
            syn_set += 1
            Qn2List.append(Qn2(seq+1))
        if flag_fin == 1 and src_ip == server_ip:
            syn_set -= 1
            if syn_set < 0:
                print("ERROR: FIN count is greater than SYN")
            else:
                no_of_tcp_flows += 1
# Qn 1 end
# Qn 2b start
        for iterat, s_port in enumerate(server_ports):
            if src_port == s_port and start_time[iterat] == -1:
                start_time[iterat] = buf[0]
                start_seq[iterat] = seq
            if dest_port == s_port and flag_fin == 1:
                final_seq[iterat] = ack
        if seq in final_seq:
            index = final_seq.index(seq)
            total_time[index] = (datetime.fromtimestamp(buf[0]) - datetime.fromtimestamp(start_time[index])).total_seconds()
            total_bytes[index] = seq - start_seq[index]
        for iterat, s_port in enumerate(server_ports):
            if dest_port == s_port:
                total_ack_packets[iterat] += 1
                if prev_ack_size[iterat] != -1:
                    if (len(last10cong[iterat]) < 1) or ((last10cong[iterat][-1] < cong_win[iterat] or last10cong[iterat][-1] >= 2*cong_win[iterat]) and len(last10cong[iterat]) < 10): 
                        last10cong[iterat].append(cong_win[iterat])
                    cong_win_free[iterat] += 1
                if ack_dest[iterat].get(ack) is None:
                    ack_dest[iterat].update({ack: 1})
                else:
                    ack_dest[iterat].update({ack: ack_dest[iterat].get(ack)+1})
                break
# Qn 2b end
# Qn 2c start
        for iterat, s_port in enumerate(server_ports):
            if src_port == s_port:
                total_packets[iterat] += 1
                if cong_win[iterat] > 0:
                    if cong_win_free[iterat] > 0:
                        cong_win_free[iterat] -= 1
                    else:
                        cong_win[iterat] += 1
                ack_set[iterat].add(ack)
                if seq in seq_set[iterat] and flag_psh != 1:
                    repeat_seq_count[iterat] += 1
                    if ack_dest[iterat].get(seq) >= 3:
                        fast_retrans[iterat] += 1
                else:
                    seq_set[iterat].add(seq)
                break
# Qn 2c end
# Qn 2a start
        for iterat, s_port in enumerate(server_ports):
            if src_port == s_port or dest_port == s_port:
                #psh packet
                if len([qn2 for qn2 in Qn2List if qn2.psh == seq]) != 0 and tcp_seg_len != 0:
                    psh_rec[iterat].append([str(seq), str(ack), str(window)])
                    qn2_obj = [qn2 for qn2 in Qn2List if qn2.psh == seq]
                    qn2_obj[0].next_psh = seq + tcp_seg_len
                    for iterat, s_port in enumerate(server_ports):
                        if src_port == s_port:
                            cong_win[iterat] += 1
                            prev_ack_size[iterat] = total_ack_packets[iterat]
                    
                #next to psh
                if len([qn2 for qn2 in Qn2List if qn2.next_psh == seq]) != 0:
                    psh_next_rec[iterat].append([str(seq), str(ack), str(window)])
                    qn2_obj = [qn2 for qn2 in Qn2List if qn2.next_psh == seq]
                    qn2_obj[0].next_psh_ack = seq + tcp_seg_len
                    
                #psh ack
                if len([qn2 for qn2 in Qn2List if qn2.next_psh == ack]) != 0:
                    psh_ack_rec[iterat].append([str(seq), str(ack), str(window)])
                    
                #next to psh ack
                if len([qn2 for qn2 in Qn2List if qn2.next_psh_ack == ack]) != 0:
                    psh_next_ack_rec[iterat].append([str(seq), str(ack), str(window)])
# Qn 2a end
    print('############################################################################')
    print('                            PART A - Q1')
    print('############################################################################')
    print("Number of TCP flows: "+str(no_of_tcp_flows))
    print('############################################################################')
    print('                            PART A - Q2a')
    print('############################################################################')
    for flno in range(no_of_tcp_flows):
        print("Flow "+str(flno))
        print("[[Seq number, Ack number, Receive Window size]]")
        print(psh_rec[flno])
        print(psh_ack_rec[flno])
        print(psh_next_rec[flno])
        print(psh_next_ack_rec[flno])
    print('############################################################################')
    print('                            PART A - Q2b')
    print('############################################################################')
    for flno in range(no_of_tcp_flows):
        print("Throughput of flow "+str(flno)+": "+str((total_bytes[flno]+total_packets[flno]*66+total_ack_packets[flno]*66)/total_time[flno]))
    print('############################################################################')
    print('                            PART A - Q2c')
    print('############################################################################')
    for flno in range(no_of_tcp_flows):
        print("Loss rate of flow "+str(flno)+": ",(repeat_seq_count[flno]/total_packets[flno]))
    print('############################################################################')
    print('                            PART A - Q2d')
    print('############################################################################')
    for flno in range(no_of_tcp_flows):
        print("Avg RTT of flow "+str(flno)+": "+str(total_time[flno]/(total_packets[flno]+total_ack_packets[flno])))
    print('############################################################################')
    print('                            PART B - Q1')
    print('############################################################################')
    for flno in range(no_of_tcp_flows):
        print("Congestion window sizes for flow "+str(flno)+": "+str(last10cong[flno]))
    print('############################################################################')
    print('                            PART B - Q2')
    print('############################################################################')
    for flno in range(no_of_tcp_flows):
        print("Flow "+str(flno))
        print(" Number of retransmission due to triple duplicate acks: "+str(fast_retrans[flno]))
        print(" Number of retransmission due to timeout: "+str(repeat_seq_count[flno]-fast_retrans[flno]))
        
def read_packets(input_pcap_file):
    with open(input_pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        parse_packs(pcap)
        
if __name__ == '__main__':
    input_pcap_file = sys.argv[1]
    read_packets(input_pcap_file)
