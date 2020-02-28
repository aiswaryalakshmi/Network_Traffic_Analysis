# Network_Traffic_Analysis
*Using TCP dump information* <br> <br>

**NOTE:** The programs have been implemented in Python3.

## How to run the program:
	python3 analysis_pcap_tcp.py Input_Files/tcp_dump.pcap
	python3 analysis_pcap_http.py http_1080.pcap tcp_1081.pcap tcp_1082.pcap
	
## Expected Result:

The code parses the byte stream and finds and stores all the required header field values. In a single pass, all the conditions relevant to the below questions are handled which reduces the complexity of the program.
1.	Number of TCP flows is calculated by counting the number of SYN/FIN pairs in the pcap file.
![](/images/Picture1.png)
2.	
	1.	The first two transactions are traced as follows:
		1.	The first PSH packet from the sender is taken.
		2.	The next packet from the client having the sequence number equal to the acknowledge number in the above PSH packet is added to the result. This completes one transaction.
		3.	The next packet from the sender having the sequence number equal to the acknowledge number in the packet mentioned in (b) is added. 
		4.	The last packet is from the client having the sequence number equal to the acknowledge number in the packet mentioned in (c). This completes the second transaction.
![](/images/Picture2.png)
	1.	Throughput is calculated as total number of bytes transmitted per unit time (in seconds). The entire packet length including all the headers is taken for calculating the throughput.
![](/images/Picture3.png)
	1.	Loss rate is (number of packets not received)/total packets sent
![](/images/Picture4.png)
	1.	Average RTT can be calculated by dividing the total time taken by the number of transactions.
![](/images/Picture5.png)
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

3.	The congestion window size is estimated at the sender side. Every server has its own initial congestion window size. The initial congestion window size is 10 in our sample file as seen from the below result. The server increases the window size linearly one by one after every acknowledge from the client as we can see from the result below. When the threshold is reached, the server increases the congestion window size to twice its current size. This can be noticed when the window size shoots up from 27 to 40 in the below result.
After every set of acknowledgements, the congestion window size is recalculated in the code by adding the number of extra packets sent after acknowledgment to the existing congestion window size.
![](/images/Picture6.png)

4.	The number of retransmissions is calculated at the sender end.
	1.	If there are at least three packets from the client with the acknowledgement number equal to the sequence number of a retransmitted packet, then it is retransmission due to triple duplicate ack.
	1.	Otherwise, if there is no acknowledgement from the client before the packet is retransmitted, then it is due to timeout.
![](/images/Picture7.png)
Below are the filters used to capture the pcap files: <br>
![](/images/Picture8.png)
![](/images/Picture9.png)
![](/images/Picture10.png)
The code parses the byte stream and finds and stores all the required header field values. In a single pass, all the conditions relevant to the below questions are handled which reduces the complexity of the program.
1.	The http part (data of tcp) is parsed to find if the packet is a HTTP request or response packet.
	1.	If the http part from the client has GET keyword in the first 4 bytes, then it is the HTTP request packet.
	1.	If the http part from the server has HTTP keyword in the first 4 bytes, then it is the HTTP response packet.
	1.	Then the requests and responses are arranged by matching the acknowledgement numbers of the requests to the sequence numbers of the responses.
![](/images/Picture11.png)
 
2.	The following logic is used to find the HTTP protocol:
	1.	The total number of TCP flows is calculated for all the 3 pcap files.
		1.	If the total number of flows is 1, then it is HTTP 2.0. It is because it uses pipelining mechanism and sends all the objects in a single flow.
		1.	If the total number of flows is equal to the total number of HTTP request/response transactions, then it is HTTP 1.0. This is because a new TCP connection is established for sending every object in the web page.
		1.	If both the above conditions do not match, then it is HTTP 1.1. It usually creates 6 TCP flows for loading a web page depending on the client’s browser configuration.
![](/images/Picture12.png)
3.	From the results below, it has been observed that the site loads the fastest under HTTP 1.0 protocol and slowest under the HTTP 2.0 protocol. <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Most packets: HTTP 1.0 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Least packets: HTTP 2.0 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Most raw bytes: HTTP 2.0 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Least raw bytes: HTTP 1.0 <br>
	Maximum number of packets are recorded for HTTP 1.0. This is because the server sends each object in a separate TCP connection. Whereas, HTTP 2.0 with the least number of flows and transactions has the minimum number of packets as well.
	The raw bytes length is maximum in HTTP 2.0. This is because of the addition of encryption information in the packets.
![](/images/Picture13.png)
