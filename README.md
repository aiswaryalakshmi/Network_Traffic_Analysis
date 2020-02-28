# Network_Traffic_Analysis
*Using TCP dump information* <br> <br>

**NOTE:** The programs have been implemented in Python3.

## How to run the program:
	python3 analysis_pcap_tcp.py Input_Files/tcp_dump.pcap
	python3 analysis_pcap_http.py http_1080.pcap tcp_1081.pcap tcp_1082.pcap
	
## Expected Result:

The code parses the byte stream and finds and stores all the required header field values. In a single pass, all the conditions relevant to the below questions are handled which reduces the complexity of the program.
1.	Number of TCP flows is calculated by counting the number of SYN/FIN pairs in the pcap file.
 
2.	
a.	The first two transactions are traced as follows:
i.	The first PSH packet from the sender is taken.
ii.	The next packet from the client having the sequence number equal to the acknowledge number in the above PSH packet is added to the result. This completes one transaction.
iii.	The next packet from the sender having the sequence number equal to the acknowledge number in the packet mentioned in (b) is added. 
iv.	The last packet is from the client having the sequence number equal to the acknowledge number in the packet mentioned in (c). This completes the second transaction.
 
b.	Throughput is calculated as total number of bytes transmitted per unit time (in seconds). The entire packet length including all the headers is taken for calculating the throughput.
 
c.	Loss rate is (number of packets not received)/total packets sent
 
d.	Average RTT can be calculated by dividing the total time taken by the number of transactions.
 
### Flow 0:
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;MSS = 1460 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;RTT = 0.00018 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;p = 0.0043 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Theorectial Throughput = 107121430.22563
### Flow 1:
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;MSS = 1460 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;RTT = 0.0007 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;p = 0.0133 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Theorectial Throughput = 15658168.2913 <br>
The theoretical throughput values for the above two flows are much larger compared to the empirical values. The deviation is because in real time, the packets do not always have the MSS size and also though the RTT is estimated after every round-trip, since the packets take different routes everytime, there is a possibility for a wide deviation in the empirical throughput value compared to the theoretical one.
### Flow 2:
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;MSS = 1460 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;RTT = 0.00063 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;p = 0.0 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Theorectial Throughput = Infinity <br>
The throughput cannot be practically infinity because of the constraints in the real world like bandwidth, etc.
