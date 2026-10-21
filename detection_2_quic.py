from scapy.all import*
from scapy.layers.quic import QUIC
from scapy.layers.quic import QUIC_Initial
from scapy.layers.quic import QUIC_Handshake
from scapy.layers.quic import QUIC_1RTT

QUIC_Initial()
QUIC_Handshake()

packets = rdpcap("D:\\netsheild project\\quic_incomplete_test.pcapng")
st=set()
for packet in packets:
    #print(packet)
    if UDP in packet and IP in packet:
       if packet[UDP].sport !=443  and packet[UDP].dport ==443:
           #print(packet)
           if Raw in packet:
               data=packet[Raw].load
               qp = QUIC(data)
               b = isinstance(qp, QUIC_Initial)
               if b == True:
                   t1=(packet[IP].src,packet[IP].dst,packet[UDP].sport,packet[UDP].dport,qp.Version, qp.DstConnID, qp.SrcConnID)
                   st.add(t1)

st1= set()                   
st2= set()               



for packet in packets:
    if UDP in packet and IP in packet:
        if packet[UDP].sport == 443 and packet[UDP].dport !=443:
            if Raw in packet:
                data1=packet[Raw].load
                qp1 = QUIC(data1)
                b1 = isinstance(qp1, QUIC_Handshake)
                b2 = isinstance(qp1, QUIC_1RTT)
                if b1 == True:
                    t2 = (packet[IP].src,packet[IP].dst,packet[UDP].sport,packet[UDP].dport,qp1.Version, qp1.DstConnID, qp1.SrcConnID)        
                    st1.add(t2)
                if b2 == True:
                    t3 = (packet[IP].src,packet[IP].dst,packet[UDP].sport,packet[UDP].dport)
                    st2.add(t3)

unm=set()
unm1=set()

fm= set()
for i in st:
    for j in st1:
        if i[0] == j[1] and i[1] == j[0] and i[2]==j[3] and i[3]==j[2] and i[5] == j[6] and i[4] == j[4]:
            a=(i[1],i[2],i[3],i[4],i[5])
            b=(j[1],j[2],j[3],j[4],j[6])
            unm.add(a)
            fm.add(i)

a=set()           
a= st-fm 

for i in a:
    for j in st2:
        if i[0]==j[1] and i[1]==j[0] and i[2]==j[3] and i[3] == j[2]:
            fm.add(i)

a=set()           
a= st-fm 


alert=False

tm=[]
h=set()
for packet in packets:
    if UDP in packet and IP in packet:
       if packet[UDP].sport !=443  and packet[UDP].dport ==443:
           if Raw in packet:
               data=packet[Raw].load
               qp = QUIC(data)
               b = isinstance(qp, QUIC_Initial)
               if b == True:
                   t1=(packet[IP].src,packet[IP].dst,packet[UDP].sport,packet[UDP].dport,qp.Version, qp.DstConnID, qp.SrcConnID)
                   if t1 in a:
                       if t1 not in h:
                           h.add(t1)
                           tm.append(packet.time)
                           if len(tm) >= 6:                                    
                                    t=tm[-1]-tm[-6]
                                    if t <= 5:
                                        print("NETSHIELD SECURITY ALERT")
                                        print("Detection Rule: Repeated Incomplete QUIC Connections")
                                        print("Status: Suspicious activity detected")
                                        with open("detection_2_quic.txt","w") as f:
                                            f.write("NETSHIELD SECURITY ALERT\n")
                                            f.write("\n")
                                            f.write("Detection Rule : Repeated Incomplete QUIC Connections\n")
                                            f.write("Status : Suspicious activity detected\n")
                                            f.write("\n")
                                            f.write(f"Unique Incomplete QUIC Connections:  {len(a)}\n")
                                            f.write(f"Detection Window: {t} seconds\n")
                                            f.write("Threshold: 6 incomplete QUIC connections within 5 seconds\n")
                                            f.write("Protocol: QUIC over UDP\n")
                                            f.write("Network Layer : IPv4")
                                        alert= True
                                        break
if alert ==False:
    print("Nothing Suspicious")