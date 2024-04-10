import socket
import tkinter as tk
from tkinter import ttk
from scapy.all import *

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("400x300")

        self.device_label = ttk.Label(root, text="Choose a device to sniff packets from:")
        self.device_label.pack(pady=10)

        self.device_combo = ttk.Combobox(root, width=40, state="readonly")
        self.device_combo.pack(pady=5)

        self.sniff_button = ttk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.sniff_button.pack(pady=5)

        self.packet_text = tk.Text(root, height=10, width=50)
        self.packet_text.pack(pady=10)

    def get_local_devices(self):
        local_devices = []
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        local_network_prefix = '.'.join(local_ip.split('.')[:-1]) + '.'

        for i in range(1, 255):
            ip = local_network_prefix + str(i)
            try:
                host = socket.gethostbyaddr(ip)
                local_devices.append((ip, host[0]))
            except:
                pass

        return local_devices

    def start_sniffing(self):
        ip_to_sniff = self.device_combo.get().split(' ')[-1]

        self.packet_text.delete('1.0', tk.END)

        def decode_packet(packet):
            if packet.haslayer(TCP):
                raw_data = packet[TCP].payload
                self.packet_text.insert(tk.END, f"TCP packet found:\n{raw_data}\n\n")
            elif packet.haslayer(HTTP):
                raw_data = packet[HTTP].payload
                self.packet_text.insert(tk.END, f"HTTP packet found:\n{raw_data}\n\n")
            elif packet.haslayer(SSL):
                raw_data = packet[SSL].payload
                self.packet_text.insert(tk.END, f"HTTPS packet found:\n{raw_data}\n\n")

        sniff(prn=decode_packet, filter=f"host {ip_to_sniff}", store=0)

    def run(self):
        self.devices = self.get_local_devices()
        device_names = [f"{device[1]} ({device[0]})" for device in self.devices]
        self.device_combo['values'] = device_names

        self.root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    app.run()
