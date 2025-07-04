import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import socket

def scan_ports():
    output_box.delete('1.0', tk.END)
    target = entry_target.get()
    for port in [21, 22, 23, 80, 443, 8080]:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((target, port))
            output_box.insert(tk.END, f"Port {port}: OPEN\n")
            s.close()
        except:
            output_box.insert(tk.END, f"Port {port}: Closed\n")

def brute_ssh():
    output_box.insert(tk.END, "Brute force started...\n")
    username = entry_target.get()
    for pw in ["1234", "password", "admin"]:
        output_box.insert(tk.END, f"Trying {pw}...\n")
        output_box.update()
    output_box.insert(tk.END, "No luck. Simulation complete.\n")

app = tk.Tk()
app.title("Penetration Toolkit")

tk.Label(app, text="Host/IP or Username:").pack()
entry_target = tk.Entry(app)
entry_target.pack()

btn_scan = tk.Button(app, text="Port Scan", command=scan_ports)
btn_scan.pack(pady=5)
btn_brute = tk.Button(app, text="SSH Brute Force", command=brute_ssh)
btn_brute.pack(pady=5)

output_box = ScrolledText(app, width=40, height=10)
output_box.pack(pady=10)

app.mainloop()
