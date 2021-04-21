import scapy
from scapy.all import *

text_file = open("Shodan_data_IPcamera_foscam.txt", "r")
lines = text_file.read().splitlines()
print(lines)
print(len(lines))
text_file.close()
# OPENS IPS TO ARRAY

# REMOVE DUPLICATE IPS FROM ARRAY
lines = list(dict.fromkeys(lines))
print("Without duplicates list ", lines)
print("Without duplicates list length", len(lines))

working_lines = []
not_working_lines = []
incremental_ipid = []
zero_ipid = []
rand_ipid = []
port_open = []
port_error = []
port_close = []
incremental_tcpid = []
zero_tcpid = []
rand_tcpid = []
syn_cookie = []
no_syn_cookie = []
linux = []
windows = []

# test1 = lines[0]
# print (test1)
# lets try scapy now

# check all for loop
# responsive
def responsive_check(test1):
    rp = sr1(IP(dst=test1) / ICMP(), timeout=1)
    if rp:
        # rp.show()
        working_lines.append(test1)
        return True
        rp = 0
    else:
        not_working_lines.append(test1)
        return False

    # ICMP NUMBER DISTRIBUTION
def ipid_classfication (test1):
    rp1 = sr1(IP(dst=test1) / ICMP(), timeout=1)
    rp2 = sr1(IP(dst=test1) / ICMP(), timeout=1)
    rp3 = sr1(IP(dst=test1) / ICMP(), timeout=1)
    if rp1 and rp2 and rp3 :
        if rp1.id == (rp2.id - 1) == (rp3.id - 2):
            incremental_ipid.append(test1)
            print("incremental_ipid count add")
        elif rp1.id == (rp2.id) == (rp3.id) == 0:
            zero_ipid.append(test1)
            print("zero_ipid count add")
        else:
            rand_ipid.append(test1)
            print("rand_ipid count add")
    else:
        rand_ipid.append(test1)
        print("rand_ipid count add")


def port80(test1):
    rp = sr1(IP(dst=test1) / TCP(dport=80, flags="S"), timeout=1)
    if rp:
        # rp.show()
        if rp.haslayer(TCP):
            s = rp.getlayer(TCP)
            # s.show()
            if s.ack == 1:
                # print("CORRECT ADDING")
                port_open.append(test1)
                return True
        else:
            # print( "ERROR ADDING")
            port_error.append(test1)
            return False
        rp = 0
    else:
        port_close.append(test1)
        return False

def tcpid_classfication(test1):
    rp1 = sr1(IP(dst=test1) / TCP(dport=80, flags="S"), timeout=1)
    rp2 = sr1(IP(dst=test1) / TCP(dport=80, flags="S"), timeout=1)
    rp3 = sr1(IP(dst=test1) / TCP(dport=80, flags="S"), timeout=1)

    if rp1:
        rp1 = rp1.getlayer(TCP)
    else:
        rp1 = sr1(IP(dst=test1) / TCP(dport=80, flags="S"), timeout=3)

    if rp2:
        rp2 = rp2.getlayer(TCP)
    else:
        rp2 = sr1(IP(dst=test1) / TCP(dport=80, flags="S"), timeout=3)

    if rp3:
        rp3 = rp3.getlayer(TCP)
    else:
        rp3 = sr1(IP(dst=test1) / TCP(dport=80, flags="S"), timeout=3)

    if rp1 and rp2 and rp3:
        if rp1.seq == (rp2.seq - 1) == (rp3.seq - 2):
            incremental_tcpid.append(test1)
            #print("incremental_ipid count add")
        elif rp1.seq == (rp2.seq) == (rp3.seq) == 0:
            zero_tcpid.append(test1)
            #print("zero_ipid count add")
        else:
            rand_tcpid.append(test1)
            #print("rand_ipid count add")
    else:
        rand_tcpid.append(test1)
        #print("rand_ipid count add")




def syncookie (test1):
    string = "tcp and host " + str(test1) + " and port 80"

    s = sr1(IP(dst=test1) / TCP(dport=80, flags="S"), timeout=3)
    rp = sniff(timeout=60, filter=string)
    if rp:
       # print("No SYN COOKIE DEPLOYED")
        syn_cookie.append(test1)
    else:
       # print("SYN COOKIE DEPLOYED")
        no_syn_cookie.append(test1)
    rp.summary()
    rp = 0

def os_detect(test1):
    s = sr1(IP(dst=test1) / ICMP(), timeout=3)
    if s:
        ip = s.getlayer(IP)
        if ip.ttl < 64:
            linux.append(test1)
        elif ip.ttl >= 64:
            windows.append(test1)



def os_detectip(test1):
    ip = sr1(IP(dst=test1) / ICMP(), timeout=3)
    if ip:
        if ip.ttl < 64:
            linux.append(test1)
        elif ip.ttl > 64:
            windows.append(test1)


for test1 in lines:
    if responsive_check(test1) == True:     # is responsive
        ipid_classfication(test1)           #IPID CLASSIFIFCATION
        if port80(test1) == True:           #POST 80 Open
            tcpid_classfication(test1)      #TCPID CLASSIFIFCATION
            syncookie(test1)               # IS SYN COOKIE USED
            os_detect(test1)                #Detect OS
        elif  port80(test1) == False:       #POST 80 Closed
            os_detect(test1)                #Detect OS





#print ("not working lines IPs ", not_working_lines)
print ("not working lines IPs count " , len(not_working_lines))

#print ("working lines IPs",working_lines)
print ("working lines IPs count ", len(working_lines))

#print ("incremental_ipid", incremental_ipid)
print ("incremental_ipid count " , len(incremental_ipid))

#print ("zero_ipid", zero_ipid)
print ("zero_ipid count " , len(zero_ipid))

#print ("rand_ipid ",rand_ipid)
print ("rand_ipid count ", len(rand_ipid))

print ("port 80 open count ", len(port_open))

print ("port 80 error reply  count ", len(port_error))

print ("port 80 close count ", len(port_close))

#print ("incremental_ipid", incremental_ipid)
print ("incremental_TCPid count " , len(incremental_tcpid))

#print ("zero_ipid", zero_ipid)
print ("zero_TCPid count " , len(zero_tcpid))

#print ("rand_ipid ",rand_ipid)
print ("rand_TCPid count ", len(rand_tcpid))

print ("SYN COOKIE DEPLOYED", len(syn_cookie))

print ("No SYN COOKIE DEPLOYED", len(no_syn_cookie))

print ("linux count ", len(linux))

print ("windows count ", len(windows))