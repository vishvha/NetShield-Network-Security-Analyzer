from scapy.all import *

packets = rdpcap("D:\\netsheild project\\capture.pcap")

flg= False

for packet in packets:
    if TCP in packet and IP in packet:
        if packet[TCP].dport == 80:
            if Raw in packet:
                data=packet[Raw].load
                if b"password=" in data or b"PASSWORD=" in data or b"passwd=" in data or b"pwd=" in data or b"USERNAME=" in data or b"username=" in data or b"pin=" in data or b"email=" in data or b"token=" in data or b"api_key=" in data:
                    print("NETSHIELD SECURITY ALERT")
                    print("Detection Rule: Cleartext Sensitive Data Exposure")
                    print("Status: Suspicious activity detected")
                    print("Protocol: HTTP over TCP")
                    print("Port: 80")
                    with open("detection_4_http.txt","w") as f:
                        f.write("NETSHIELD SECURITY ALERT\n")
                        f.write("\n")
                        f.write("Detection Rule: Cleartext Sensitive Data Exposure\n")
                        f.write("Status: Suspicious activity detected\n")
                        f.write("\n")
                        f.write("Reason: Sensitive information detected in unencrypted HTTP traffic\n")
                        f.write("Protocol: HTTP over TCP\n")
                        f.write("Port: 80\n")
                        f.write("Network Layer: IPv4\n")
                    flg = True


if flg == False:
    print("Nothing suspicious")