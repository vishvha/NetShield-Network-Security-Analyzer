from scapy.all import*
from scapy.layers.quic import QUIC
from scapy.layers.quic import QUIC_Initial
from scapy.layers.quic import QUIC_Handshake
from scapy.layers.quic import QUIC_1RTT

QUIC_Initial()
QUIC_Handshake()

packets = rdpcap("D:\\netsheild project\\roughcapture.pcapng")
st=set()
for packet in packets:
    #print(packet)
    if UDP in packet:
       if packet[UDP].sport !=443  and packet[UDP].dport ==443:
           #print(packet)
           if Raw in packet:
               data=packet[Raw].load
               qp = QUIC(data)
               b = isinstance(qp, QUIC_Initial)
               if b == True:
                   #print(packet,packet[UDP].sport,packet[UDP].dport, packet.time,"ver", qp.Version,"dstid", qp.DstConnID,"src", qp.SrcConnID,"number", qp. PacketNumber)
                   #print(type(packet.time))
                   t1=(packet[IP].src,packet[IP].dst,packet[UDP].sport,packet[UDP].dport,qp.Version, qp.DstConnID, qp.SrcConnID)
                   #print(type(t1[2]))
                   st.add(t1)

st1= set()                   
st2= set()               

#print(st(DstConnID, SrcConnID))
#print(st)


for packet in packets:
    if UDP in packet:
        if packet[UDP].sport == 443 and packet[UDP].dport !=443:
            if Raw in packet:
                data1=packet[Raw].load
                qp1 = QUIC(data1)
                b1 = isinstance(qp1, QUIC_Handshake)
                b2 = isinstance(qp1, QUIC_1RTT)
                if b1 == True:
                    t2 = (packet[IP].src,packet[IP].dst,packet[UDP].sport,packet[UDP].dport,qp1.Version, qp1.DstConnID, qp1.SrcConnID)
                    #            1            2            3                4                      5        6                                  
                    st1.add(t2)
                if b2 == True:
                    t3 = (packet[IP].src,packet[IP].dst,packet[UDP].sport,packet[UDP].dport)
                    st2.add(t3)


"""print("Actual connection",len(st))
for i in st:
    print(i)

print("\n")
print("reversed connection",len(st1))
for j in st1:
    print(j)"""
unm=set()
unm1=set()


fm= set()
for i in st:
    #print(i)
    for j in st1:
        #print(j)
        if i[0] == j[1] and i[1] == j[0] and i[2]==j[3] and i[3]==j[2] and i[5] == j[6] and i[4] == j[4]:
            #print(i[1],i[2],i[3],i[4],i[5], " = ",j[1],j[2],j[3],j[4],j[6])
            a=(i[1],i[2],i[3],i[4],i[5])
            b=(j[1],j[2],j[3],j[4],j[6])
            unm.add(a)
            
            fm.add(i)
            #print(len(fm))
            #if st not in fm:
                #print(len(st))
                #print(len(fm))

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
#print(len(a))
for packet in packets:
    #print(packet)
    if UDP in packet:
       if packet[UDP].sport !=443  and packet[UDP].dport ==443:
           #print(packet)
           if Raw in packet:
               data=packet[Raw].load
               qp = QUIC(data)
               b = isinstance(qp, QUIC_Initial)
               if b == True:
                   #print(packet,packet[UDP].sport,packet[UDP].dport, packet.time,"ver", qp.Version,"dstid", qp.DstConnID,"src", qp.SrcConnID,"number", qp. PacketNumber)
                   #print(type(packet.time))
                   t1=(packet[IP].src,packet[IP].dst,packet[UDP].sport,packet[UDP].dport,qp.Version, qp.DstConnID, qp.SrcConnID)
                   if t1 in a:
                       if t1 not in h:
                           h.add(t1)
                           tm.append(packet.time)
                           if len(tm) >= 6:                                    
                                    #print(len(tm))
                                    t=tm[-1]-tm[-6]
                                    if t <= 5:
                                        print("ALERT !!!, NEEDS INVESTIGATION IN QUIC/UDP")
                                        alert= True
                                        break
if alert ==False:
    print("False Positive")