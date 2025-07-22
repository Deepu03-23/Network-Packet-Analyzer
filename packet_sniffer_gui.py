import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import threading
import asyncio
import pyshark

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer - Educational Use Only")

        # Ethical Notice
        notice = (
            "⚠️ Educational Use Only\n"
            "This tool is intended strictly for learning and research.\n"
            "Do NOT use it to capture unauthorized or private data.\n"
            "Always follow legal and ethical guidelines."
        )
        self.notice_label = tk.Label(root, text=notice, fg="red", font=("Arial", 10, "bold"))
        self.notice_label.pack(padx=10, pady=(10, 0))

        # Display Area
        self.text_area = ScrolledText(root, width=100, height=30, font=("Consolas", 10))
        self.text_area.pack(padx=10, pady=10)

        # Buttons
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=(0, 10))

        self.start_btn = tk.Button(btn_frame, text="Start Capture", command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(btn_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.capturing = False
        self.capture_thread = None

    def start_capture(self):
        if not self.capturing:
            self.capturing = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.text_area.delete('1.0', tk.END)
            self.text_area.insert(tk.END, "Starting packet capture...\n")
            self.capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
            self.capture_thread.start()

    def stop_capture(self):
        if self.capturing:
            self.capturing = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.text_area.insert(tk.END, "\nPacket capture stopped.\n")

    def capture_packets(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # List of known interfaces
        interfaces = [
            '\\Device\\NPF_{6911D06C-A80B-40A4-9F80-516C26A5FFBF}',
            '\\Device\\NPF_{6122509F-4C59-4C48-928D-9A5B132B6BD4}',
            '\\Device\\NPF_{6EC293BB-3D66-4B3B-AE4E-62F18800AB6D}',
            '\\Device\\NPF_{82CBA760-EA6F-4687-BD58-B231D252E59F}',
            '\\Device\\NPF_{4F70A5A2-6921-4E54-8C0C-1DA18A366D87}',
            '\\Device\\NPF_{64A69FB3-1CA5-4D0E-B162-327F0DE05A8C}'
        ]

        working_interface = None
        self.text_area.insert(tk.END, "Detecting active network interface...\n")
        self.text_area.see(tk.END)

        for iface in interfaces:
            try:
                capture = pyshark.LiveCapture(interface=iface)
                capture.sniff(timeout=2)
                if len(capture) > 0:
                    working_interface = iface
                    self.text_area.insert(tk.END, f"✅ Active interface found: {iface}\n")
                    self.text_area.see(tk.END)
                    break
            except Exception as e:
                self.text_area.insert(tk.END, f"❌ Failed on {iface}: {e}\n")
                self.text_area.see(tk.END)

        if not working_interface:
            self.text_area.insert(tk.END, "❌ No active interface found. Cannot start capture.\n")
            self.text_area.see(tk.END)
            return

        def analyze_packet(pkt):
            if not self.capturing:
                raise KeyboardInterrupt

            try:
                src = pkt.ip.src
                dst = pkt.ip.dst
                proto = pkt.highest_layer
                payload = "[No payload]"

                if hasattr(pkt, 'data'):
                    raw = bytes.fromhex(pkt.data.data.replace(':', ''))
                    try:
                        payload = raw.decode('utf-8', errors='replace')[:100]
                    except:
                        payload = "[Binary data]"

                display = (
                    f"\n--- Packet Captured ---\n"
                    f"Source IP: {src}\n"
                    f"Destination IP: {dst}\n"
                    f"Protocol: {proto}\n"
                    f"Payload (first 100 chars):\n{payload}\n"
                    f"--------------------------\n"
                )

                self.text_area.insert(tk.END, display)
                self.text_area.see(tk.END)

            except AttributeError:
                self.text_area.insert(tk.END, "\n[Unsupported or Non-IP Packet]\n")
                self.text_area.see(tk.END)

        try:
            capture = pyshark.LiveCapture(interface=working_interface)
            capture.apply_on_packets(analyze_packet, timeout=None)
        except KeyboardInterrupt:
            pass

def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
