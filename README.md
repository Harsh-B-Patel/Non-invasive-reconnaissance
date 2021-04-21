# non-invasive-reconnaissance
Scapy program which will allow you to do non-invasive reconnaissance on a list of remote networked devices. 
The Program check if the IP address: 
A. Device is responsive [yes/no]
B. IP-ID counter deployed by device (in ICMP pkts) [zero/incremental/random]
C. Port 80 on device is open [yes/no]
D. IP-ID counter deployed by device (in TCP pkts) [zero/incremental/random] 
E. SYN cookies deployed by device [yes/no]
F. Likely OS system deployed on the device [Linux/Windows]


A sample Shodan list of remote IPs is provided to test the scrypt.


Sample Scrypt run output: 

![Sample Script Output](https://user-images.githubusercontent.com/46072683/115493908-94983680-a232-11eb-97db-364134ca20b0.png)
