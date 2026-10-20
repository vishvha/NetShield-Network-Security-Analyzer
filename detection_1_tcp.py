from scapy.all import *
packets = rdpcap("D:\\netsheild project\\pkt.TCP.synflood.spoofed.pcap")
st=set()
st1=set()

for packet in packets:
    if TCP in packet and IP in packet:
        if packet[TCP].flags == 'S':
            #print(packet, "SEQ =",packet[TCP].seq)
            #print(packet[IP].src) #is that do u want me to copy info for set from here 
            t = (
                packet[IP].src,
                packet[IP].dst,
                packet[TCP].sport,
                packet[TCP].dport,
                packet[TCP].seq
                )
            #print(t)
            st.add(t)
        if packet[TCP].flags == "SA":
            #print(pckt)
            t1 = (
                packet[IP].src,
                packet[IP].dst,
                packet[TCP].sport,
                packet[TCP].dport,
                packet[TCP].seq
                )
            st1.add(t1)
unm=set()

for syn in st:
    found=False 
    for sa in st1:
        if syn[0] == sa[1] and syn[1] == sa[0] and syn[2] == sa[3] and syn[3] == sa[2]:
            #print(syn[0],syn[1],syn[2],syn[3]," = ",sa[0],sa[1],sa[2],sa[3])
            found = True
            break
    if found == False:
        #print("\n !!! UNMATCH  ",syn[0],syn[1],syn[2],syn[3],"\n")    
        b=syn[0],syn[1],syn[2],syn[3],syn[4]
        unm.add(b)


tm=[]

alert=False
mts=set()
#packet = rdpcap("D:\\netsheild project\\pkt.TCP.synflood.spoofed.pcap")

if len(unm) >= 6:
    for pkt in packets:
        if TCP in pkt and IP in pkt:
            if pkt[TCP].flags == 'S':
                t2=(
                    pkt[IP].src,
                    pkt[IP].dst,
                    pkt[TCP].sport,
                    pkt[TCP].dport,
                    pkt[TCP].seq                
                )
                #print(t2,pkt[TCP].seq)
                if t2 in unm and t2 not in mts:
                    tm.append(pkt.time)
                    mts.add(t2)
                    #print(tm,len(tm))
                    
                if len(tm) >= 6:
                    #print(len(tm))
                    time_diff=tm[-1]-tm[-6]
                    if time_diff <= 5:
                        print("NETSHIELD SECURITY ALERT")
                        print("Detection Rule : Repeated Failed TCP Connections")
                        print("Status : Suspicious activity detected")
                        print("Unique Failed SYNs",len(unm))
                        print("Detection Window",time_diff,"seconds")
                        with open("Detection_1_Report.txt","w") as f:
                            f.write("NETSHIELD SECURITY ALERT\n")
                            f.write("\n")
                            f.write("Detection Rule: Repeated Failed TCP Connections\n")
                            f.write("Status: Suspicious activity detected\n")
                            f.write("\n")
                            f.write(f"Unique Failed SYNs :{len(unm)} \n")
                            f.write(f"Detection Window:{time_diff} seconds\n")
                            f.write(f"Threshold : 6 failed SYNs within 5 Seconds\n")
                            f.write("Protocol : TCP\n")
                            f.write("Network Layer : IPv4\n")
                        alert= True
                        break
    if alert==False:
        print("Nothing suspicious")
else:
    print("Nothing suspicious")
