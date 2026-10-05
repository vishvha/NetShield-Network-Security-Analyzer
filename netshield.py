from scapy.all import *
packets = rdpcap("D:\\netsheild project\\pkt.TCP.synflood.spoofed.pcap")
st=set()
for packet in packets:
    if TCP in packet:
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
"""print("\nThis is from set")
for i in st:
    print(i)
print("\n This is reversed")
for i in st:
    print(i[1], i[3], "->", i[0], i[2])"""


#print("\n This part changes to SA filtering \n")
#pckt =rdpcap("D:\\netsheild project\\pkt.TCP.synflood.spoofed.pcap")
st1=set()
for pckt in packets:
    if TCP in pckt:
        if pckt[TCP].flags == "SA":
            #print(pckt)
            t1 = (
                pckt[IP].src,
                pckt[IP].dst,
                pckt[TCP].sport,
                pckt[TCP].dport,
                pckt[TCP].seq
                )
            st1.add(t1)
"""
for o in st1:
    print(o[1], o[3], "->", o[0], o[2])"""



unm=set()
a=0
print("\nFinal comaprision :")
for syn in st:
    found=False 
    for sa in st1:
        if syn[0] == sa[1] and syn[1] == sa[0] and syn[2] == sa[3] and syn[3] == sa[2]:
            print(syn[0],syn[1],syn[2],syn[3]," = ",sa[0],sa[1],sa[2],sa[3])
            found = True
            break
    if found == False:
        #print("\n !!! UNMATCH  ",syn[0],syn[1],syn[2],syn[3],"\n")    
        a+=1
        b=syn[0],syn[1],syn[2],syn[3],syn[4]
        unm.add(b)

print("\n",a ,"unmatch found ")
#print(unm)
tm=[]

alert=False
mts=set()
#packet = rdpcap("D:\\netsheild project\\pkt.TCP.synflood.spoofed.pcap")

if len(unm) >= 6:
    for pkt in packets:
        if TCP in pkt:
            if pkt[TCP].flags == 'S':
                t2=(
                    pkt[IP].src,
                    pkt[IP].dst,
                    pkt[TCP].sport,
                    pkt[TCP].dport,
                    pkt[TCP].seq                
                )
                #print(t2,pkt[TCP].seq)
                """if i[0]==pkt[IP].src and i[1]==pkt[IP].dst and i[2]==pkt[TCP].sport and i[3]==pkt[TCP].dport and i[4]==pkt[TCP].seq:
                    print(pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].seq, pkt[TCP].flags, pkt[TCP].time)"""
                if t2 in unm and t2 not in mts:
                    tm.append(pkt.time)
                    mts.add(t2)
                    #print(tm,len(tm))
                    
                if len(tm) >= 6:
                    print(len(tm))
                    t=tm[-1]-tm[-6]
                    if t <= 5:
                        print("Unique Failed SYNs:",len(unm))
                        print("The time Difference between the failed packets are ",t,"!!!Might be a ALERT to be verified")
                        print("The time difference: ",t)
                        alert= True
                        break
    if alert==False:
        print("Nothing suspicious")
else:
    print("Nothing suspicious")
        
                    
            
        #if len(unm) >= 6:
"""   
    t=tm[-1]-tm[-6]
    if t <= 5:
        print("Unique Failed SYNs:",len(unm))
        print("The time Difference between the failed packets are ",t,"!!!Might be a ALERT to be verified")
        print("The time difference: ",t)
    else:
        print("Nothing suspicious")
        print("The time difference: ",t)"""