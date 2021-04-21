# Non-Invasive Reconnaissance
Scapy program which will allow you to do non-invasive reconnaissance on a list of remote networked devices. 

The Program check if the IP address: 
- Device is responsive [yes/no]
- IP-ID counter deployed by device (in ICMP pkts) [zero/incremental/random]
- Port 80 on device is open [yes/no]
- IP-ID counter deployed by device (in TCP pkts) [zero/incremental/random] 
- SYN cookies deployed by device [yes/no]
- Likely OS system deployed on the device [Linux/Windows]


A sample Shodan list of remote IPs is provided to test the scrypt.
Sample Scrypt run output: 

![Sample Script Output](https://user-images.githubusercontent.com/46072683/115493908-94983680-a232-11eb-97db-364134ca20b0.png)
