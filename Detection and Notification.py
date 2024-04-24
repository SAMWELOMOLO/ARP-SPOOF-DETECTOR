
import scapy.all as scapy
import tkinter as tk
from threading import Thread

# Function to display notifications
def show_notification(message):
    root = tk.Tk()
    root.title("ARP Spoofing Detector")
    label = tk.Label(root, text=message, font=("Arial", 16))
    label.pack(pady=10)
    root.overrideredirect(True) 
    root.attributes("-alpha", 1.0)
    root.after(2000, root.destroy)
    root.mainloop()

# Function to get the MAC address of an IP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

# Function to sniff packets on a specific interface
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

# Function to process sniffed packets for ARP spoofing
def process_sniffed_packet(packet):
    if scapy.ARP in packet and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac != response_mac:
                block_attacker(packet, real_mac)
                notification_message = "🎉 ARP Spoofing detected." 
                notification_thread = Thread(target=show_notification, args=(notification_message,))
                notification_thread.start()
        except IndexError:
            pass



# Function to handle multiple interfaces
def handle_interfaces(interfaces):
    for interface in interfaces:
        sniff_thread = Thread(target=sniff, args=(interface,))
        sniff_thread.start()

# Interfaces list
interfaces = ["wlp2s0", "enp1s0"]
handle_interfaces(interfaces)

