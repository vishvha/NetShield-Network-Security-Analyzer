from scapy.all import *

packets = rdpcap("D:\\netsheild project\\roughcapture.pcapng")

flg= False

for packet in packets:
    if TCP in packet:
        if packet[TCP].dport == 80:
            if Raw in packet:
                data=packet[Raw].load
                if b"password=" in data or b"passwd=" in data or b"pwd=" in data or b"pin=" in data or b"email=" in data or b"token=" in data or b"api_key=" in data:
                    print("!!Alert - Sensitive data detected",packet)
                    print(data)
                    flg = True


if flg == False:
    print("Nothing suspicious")

packets = rdpcap("D:\\netsheild project\\capture.pcap")

flg= False

for packet in packets:
    if TCP in packet:
        if packet[TCP].dport == 80:
            if Raw in packet:
                data=packet[Raw].load
                if b"password=" in data or b"PASSWORD=" in data or b"passwd=" in data or b"pwd=" in data or b"USERNAME=" in data or b"username=" in data or b"pin=" in data or b"email=" in data or b"token=" in data or b"api_key=" in data:
                    print("!!Alert - Sensitive data detected",packet)
                    flg = True


if flg == False:
    print("Nothing suspicious")

#username password email token login/form data
