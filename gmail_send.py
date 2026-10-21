from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build 
from email.message import EmailMessage
import base64

msg=EmailMessage()

creds = Credentials.from_authorized_user_file("token.json")

service = build("gmail", "v1", credentials=creds)

msg["From"] = "yoursender@gmail.com" # Sender Gmail id 
msg["To"] = "yourreceiver@gmail.com" # Receiver email id 
msg["Subject"] = "NetShield Reports"

with open("detection_1_tcp.txt","r") as f:
    report1 = f.read()

with open("detection_2_quic.txt","r") as f:
    report2 = f.read()

with open("detection_3_ssdp.txt","r") as f:
    report3 = f.read()

with open("detection_4_http.txt","r") as f:
    report4 = f.read()

with open("detection_5_dns.txt","r") as f:
    report5 = f.read()

msg.set_content("""This email contains the detailed NetShield detection 
reports generated from the analyzed PCAP traffic.""")

msg.add_attachment(
    report1,
    subtype="plain",
    filename="detection_1_tcp.txt"
   )

msg.add_attachment(
    report2,
    subtype="plain",
    filename="detection_2_quic.txt"
   )

msg.add_attachment(
    report3,
    subtype="plain",
    filename="detection_3_ssdp.txt"
   )

msg.add_attachment(
    report4,
    subtype="plain",
    filename="detection_4_http.txt"
   )

msg.add_attachment(
    report5,
    subtype="plain",
    filename="detection_5_dns.txt"
   )

enc= msg.as_bytes()
enc_msg = base64.urlsafe_b64encode(enc).decode()

d={
    "raw":enc_msg
}

service.users().messages().send(
    userId="me",
    body=d
).execute()