from scapy.all import *

packets = rdpcap("D:\\netsheild project\\file.pcap")

d = {}

# Collect SSDP timestamps for each IPv4 source
for packet in packets:
    if UDP in packet and IP in packet:

        if packet[UDP].dport == 1900 or packet[UDP].sport == 1900:

            src_ip = packet[IP].src

            if src_ip not in d:
                d[src_ip] = [packet.time]

            else:
                d[src_ip].append(packet.time)


alert = False

# Check each source separately
for ip, times in d.items():

    if len(times) >= 5:

        for i in range(len(times) - 4):

            time_difference = times[i + 4] - times[i]

            if time_difference <= 1:

                print("ALERT !!! HIGH-VOLUME SSDP BURST")
                print("Source IP:", ip)
                print("5 SSDP packets detected within:", time_difference, "seconds")

                alert = True
                break

    if alert:
        break


if not alert:
    print("Nothing suspicious")



