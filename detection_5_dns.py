from scapy.all import *

packets = rdpcap("D:\\netsheild project\\dns.pcap")

flag=False
cnt =0
st=set()

for packet in packets:
    if UDP in packet and DNS in packet:
        if packet[UDP].dport ==53 or packet[UDP].sport ==53:
            if packet[DNS].qr ==0 and packet[DNS].qd is not None:
                a=packet[DNS].qd.qname
                if b"." in a :
                    b=a.find(b".")
                    dns=a[:b]
                    if len(dns) > 25:
                        st.add(dns)
                        cnt +=1
                        flag=True
if flag == True:
    print("NETSHIELD SECURITY ALERT")
    print("Detection Rule: Suspicious DNS Subdomains")
    print("Status: Suspicious activity detected")
    print("Total Suspicious Queries:", cnt)
    print("Unique Suspicious DNS Labels:", len(st))
    with open("detection_5_dns.txt", "w") as f:
        f.write("NETSHIELD SECURITY ALERT\n")
        f.write("\n")
        f.write("Detection Rule: Suspicious DNS Subdomains\n")
        f.write("Status: Suspicious activity detected\n")
        f.write("\n")
        f.write(f"Total Suspicious Queries: {cnt}\n")
        f.write(f"Unique Suspicious DNS Labels: {len(st)}\n")
        f.write("Threshold: First DNS label longer than 25 characters\n")
        f.write("Protocol: DNS over UDP\n")
        f.write("Port: 53\n")
        f.write("Network Layer: IPv4\n")



elif flag == False:
    print("Nothing suspicious")