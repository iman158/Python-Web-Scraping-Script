import scapy.all as scapy
import whois
import tkinter as tk
from tkinter import scrolledtext

def process_packet(packet):
    if packet.haslayer(scapy.TCP) and (packet.haslayer(scapy.Raw) or packet.haslayer(scapy.HTTP)):
        payload = str(packet[scapy.Raw].load) if packet.haslayer(scapy.Raw) else ""

        if "HTTP" in payload:
            print(f"HTTP packet found:\n{packet.summary()}\nPayload: {payload}")

            # Extract some information from the payload
            http_packet = scapy.TCP(packet.getlayer(scapy.TCP))
            http_load = http_packet[scapy.Raw].load.decode("utf-8", "ignore")
            headers, body = http_load.split("\r\n\r\n", 1)

            print("Headers:")
            for line in headers.split("\r\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    print(f"{key.strip()}: {value.strip()}")

            print("Body:\n" + body)

        elif "HTTPS" in payload:
            # HTTPS packets are encrypted, so we can't inspect the payload directly
            print(f"HTTPS packet found:\n{packet.summary()}\nPayload: {payload}")

            # Extract some information from the packet
            https_packet = scapy.TCP(packet.getlayer(scapy.TCP))
            cert = whois.Certificates(str(https_packet[scapy.Raw].load))
            print(f"Subject: {cert.subject}")

def start_sniffing():
    scapy.sniff(prn=process_packet, store=False)

# GUI
window = tk.Tk()
window.title("Packet Sniffer")

text_area = scrolledtext.ScrolledText(window, width=80, height=20)
text_area.grid(column=0, row=0, padx=10, pady=10)

start_button = tk.Button(window, text="Start Sniffing", command=start_sniffing)
start_button.grid(column=0, row=1, pady=10)

window.mainloop()
