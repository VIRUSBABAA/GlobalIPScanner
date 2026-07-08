#!/usr/bin/env python3
"""
Random IP Scanner - finds web servers with specific technologies.
Generates random IPv4 addresses, scans them for WordPress, Laravel, etc.
Runs until you click Stop. No duplicates.
"""

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import random
import ipaddress
import requests
import threading
import time
import socket
import json
import csv
import io
from urllib.parse import urlparse
from queue import Queue, Empty

# ---------- Scanner Logic (Improved) ----------
class IPScanner:
    def __init__(self, output_file, threads=20, timeout=3, ports="80,443", export_format="txt"):
        self.output_file = output_file
        self.threads = threads
        self.timeout = timeout
        self.ports = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        self.export_format = export_format
        self.running = False
        self.stop_flag = False
        self.found_ips = {}          # ip -> list of detected techs
        self.scanned_ips = set()     # all scanned ips (to avoid duplicate scanning)
        self.lock = threading.Lock()
        self.queue = Queue()
        self.processed_count = 0
        self.found_count = 0
        self.session = None
        self.workers = []

    def start(self):
        self.running = True
        self.stop_flag = False
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = self.timeout
        # start worker threads
        self.workers = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            self.workers.append(t)
        # fill queue with random IPs (pre‑generate to distribute work)
        self._fill_queue()

    def _fill_queue(self):
        # initially fill queue with some IPs
        for _ in range(self.threads * 10):
            self.queue.put(self.generate_random_ip())

    def generate_random_ip(self):
        while True:
            ip_int = random.randint(0x01000000, 0xFE000000)
            ip_str = str(ipaddress.IPv4Address(ip_int))
            if ipaddress.ip_address(ip_str).is_global:
                return ip_str

    def worker(self):
        while self.running and not self.stop_flag:
            try:
                ip = self.queue.get(timeout=1)
            except Empty:
                # refill queue if empty
                if self.running and not self.stop_flag:
                    for _ in range(self.threads * 5):
                        self.queue.put(self.generate_random_ip())
                continue
            # check if already scanned
            with self.lock:
                if ip in self.scanned_ips:
                    continue
                self.scanned_ips.add(ip)
            self.scan_ip(ip)
            self.queue.task_done()

    def scan_ip(self, ip):
        found_techs = []
        for port in self.ports:
            if self.stop_flag:
                break
            scheme = 'https' if port == 443 else 'http'
            try:
                # quick socket check
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result != 0:
                    continue
                # HTTP request
                url = f"{scheme}://{ip}:{port}" if port not in (80,443) else f"{scheme}://{ip}"
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if resp.status_code >= 400:
                    continue
                # Detect technologies
                techs = self.detect_technology(resp, ip)
                if techs:
                    found_techs.extend(techs)
                    # if we found something, we can stop scanning other ports for this IP
                    break
            except Exception:
                continue

        if found_techs:
            with self.lock:
                if ip not in self.found_ips:
                    self.found_ips[ip] = list(set(found_techs))  # deduplicate
                    self.found_count += 1
                    self.save_result(ip, self.found_ips[ip])

        with self.lock:
            self.processed_count += 1

    def detect_technology(self, resp, ip):
        headers = str(resp.headers).lower()
        body = resp.text.lower()[:20000]  # limit body size for speed
        detected = []

        # Check headers
        if 'x-powered-by' in headers:
            if 'php' in headers:
                detected.append('PHP')
            if 'asp.net' in headers:
                detected.append('ASP.NET')
        if 'server' in headers:
            if 'nginx' in headers:
                detected.append('Nginx')
            elif 'apache' in headers:
                detected.append('Apache')
            elif 'iis' in headers:
                detected.append('IIS')
        if 'wp-json' in headers or 'wordpress' in headers:
            detected.append('WordPress')
        if 'laravel' in headers or 'laravel' in body:
            detected.append('Laravel')
        if 'yii' in body:
            detected.append('Yii')
        if 'codeigniter' in body:
            detected.append('CodeIgniter')
        if 'phpinfo' in body:
            detected.append('PHPInfo')
        if 'config.json' in body:
            detected.append('Config JSON')
        if '.git' in body or 'git/HEAD' in body:
            detected.append('.git exposed')
        if 'frontdev' in body:
            detected.append('FrontDev')

        # Additional checks for common files
        extra_paths = [
            ('/.git/HEAD', '.git exposed'),
            ('/config.json', 'Config JSON'),
            ('/phpinfo.php', 'PHPInfo'),
            ('/wp-admin/', 'WordPress Admin'),
            ('/app/etc/local.xml', 'Magento'),
            ('/vendor/autoload.php', 'Composer'),
        ]
        for path, label in extra_paths:
            try:
                # use ip from resp.url to determine scheme
                scheme = 'https' if 'https' in resp.url else 'http'
                url = f"{scheme}://{ip}{path}"
                r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if r.status_code == 200:
                    detected.append(label)
            except:
                pass

        return list(set(detected))

    def save_result(self, ip, techs):
        # Save to output file based on format
        try:
            if self.export_format == "txt":
                with open(self.output_file, 'a', encoding='utf-8') as f:
                    f.write(f"{ip} - {', '.join(techs)}\n")
            elif self.export_format == "csv":
                with open(self.output_file, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([ip, ', '.join(techs)])
            elif self.export_format == "json":
                # For JSON, we'll rewrite the whole file each time (simplest)
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    json.dump(self.found_ips, f, indent=2)
        except Exception as e:
            print(f"Error saving: {e}")

    def stop(self):
        self.stop_flag = True
        self.running = False
        # close session
        if self.session:
            self.session.close()
        # wait for threads to finish
        for t in self.workers:
            t.join(timeout=0.5)


# ---------- GUI (Enhanced) ----------
class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Random IP Scanner - Tech Finder")
        self.root.geometry("800x600")
        self.root.resizable(True, True)

        # Styles
        self.style = ttk.Style()
        try:
            self.style.theme_use('clam')  # modern base
        except:
            pass
        self.style.configure('TButton', font=('Segoe UI', 10), padding=6)
        self.style.configure('TLabel', font=('Segoe UI', 10))
        self.style.configure('Header.TLabel', font=('Segoe UI', 14, 'bold'), foreground='#1a5276')
        self.style.configure('Banner.TLabel', font=('Segoe UI', 12), foreground='#2c3e50')
        self.style.configure('Accent.TButton', background='#2980b9', foreground='white')
        self.style.map('Accent.TButton', background=[('active', '#1f618d')])

        # Variables
        self.output_file = tk.StringVar(value="found_ips.txt")
        self.thread_count = tk.IntVar(value=20)
        self.timeout_val = tk.IntVar(value=3)
        self.ports_val = tk.StringVar(value="80,443")
        self.export_format = tk.StringVar(value="txt")
        self.scanner = None
        self.running = False

        self.create_widgets()

    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # ------ Banner ------
        banner_frame = ttk.Frame(main_frame)
        banner_frame.pack(fill=tk.X, pady=(0,10))

        banner_label = ttk.Label(banner_frame, text="🔍 RANDOM IP SCANNER", style='Header.TLabel')
        banner_label.pack()

        creator_label = ttk.Label(banner_frame, text="TOOL CREATED BY VIRUSBABA", style='Banner.TLabel')
        creator_label.pack()

        link_label = ttk.Label(banner_frame, text="Contact: https://www.linkedin.com/in/muhammad-subhan-28a638327",
                               foreground='blue', cursor='hand2')
        link_label.pack()
        link_label.bind("<Button-1>", lambda e: self.open_link("https://www.linkedin.com/in/muhammad-subhan-28a638327"))

        # ------ Settings Frame ------
        settings_frame = ttk.LabelFrame(main_frame, text="Settings", padding=10)
        settings_frame.pack(fill=tk.X, pady=5)

        # Row 1: Output file
        row1 = ttk.Frame(settings_frame)
        row1.pack(fill=tk.X, pady=2)
        ttk.Label(row1, text="Output File:").pack(side=tk.LEFT, padx=5)
        entry_out = ttk.Entry(row1, textvariable=self.output_file, width=40)
        entry_out.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        ttk.Button(row1, text="Browse...", command=self.browse_output).pack(side=tk.LEFT, padx=5)

        # Row 2: Threads, Timeout, Ports
        row2 = ttk.Frame(settings_frame)
        row2.pack(fill=tk.X, pady=2)
        ttk.Label(row2, text="Threads:").pack(side=tk.LEFT, padx=5)
        ttk.Spinbox(row2, from_=5, to=100, textvariable=self.thread_count, width=6).pack(side=tk.LEFT, padx=5)
        ttk.Label(row2, text="Timeout (s):").pack(side=tk.LEFT, padx=5)
        ttk.Spinbox(row2, from_=1, to=30, textvariable=self.timeout_val, width=6).pack(side=tk.LEFT, padx=5)
        ttk.Label(row2, text="Ports:").pack(side=tk.LEFT, padx=5)
        ttk.Entry(row2, textvariable=self.ports_val, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Label(row2, text="Format:").pack(side=tk.LEFT, padx=5)
        format_combo = ttk.Combobox(row2, textvariable=self.export_format, values=["txt", "csv", "json"], width=6)
        format_combo.pack(side=tk.LEFT, padx=5)

        # ------ Controls ------
        ctrl_frame = ttk.Frame(main_frame)
        ctrl_frame.pack(fill=tk.X, pady=5)

        self.btn_start = ttk.Button(ctrl_frame, text="▶ Start Scanning", command=self.start_scan, style='Accent.TButton')
        self.btn_start.pack(side=tk.LEFT, padx=5)

        self.btn_stop = ttk.Button(ctrl_frame, text="⏹ Stop", command=self.stop_scan, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        self.btn_clear_log = ttk.Button(ctrl_frame, text="Clear Log", command=self.clear_log)
        self.btn_clear_log.pack(side=tk.LEFT, padx=5)

        # ------ Progress ------
        prog_frame = ttk.Frame(main_frame)
        prog_frame.pack(fill=tk.X, pady=5)
        self.progress_var = tk.StringVar(value="Scanned: 0 | Found: 0 | Current IP: -")
        ttk.Label(prog_frame, textvariable=self.progress_var).pack(side=tk.LEFT)
        self.progress_bar = ttk.Progressbar(prog_frame, orient="horizontal", length=400, mode="indeterminate")
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=10)

        # ------ Found IPs List ------
        list_frame = ttk.LabelFrame(main_frame, text="Found IPs (with Technologies)", padding=5)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Use Treeview for better display
        columns = ('IP', 'Technologies')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=10)
        self.tree.heading('IP', text='IP Address')
        self.tree.heading('Technologies', text='Detected Technologies')
        self.tree.column('IP', width=150)
        self.tree.column('Technologies', width=300)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # ------ Log ------
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=6, font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.log("Ready. Click 'Start Scanning' to begin.")

    def open_link(self, url):
        import webbrowser
        webbrowser.open_new(url)

    def log(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)

    def browse_output(self):
        f = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("CSV", "*.csv"), ("JSON", "*.json"), ("All files", "*.*")])
        if f:
            self.output_file.set(f)

    def start_scan(self):
        if self.running:
            return
        output = self.output_file.get().strip()
        if not output:
            messagebox.showerror("Error", "Please specify an output file.")
            return
        try:
            with open(output, 'a') as f:
                pass
        except:
            messagebox.showerror("Error", "Cannot write to output file.")
            return

        self.running = True
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.progress_bar.start(10)

        # Clear found list
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.scanner = IPScanner(
            output,
            threads=self.thread_count.get(),
            timeout=self.timeout_val.get(),
            ports=self.ports_val.get(),
            export_format=self.export_format.get()
        )
        self.scanner.start()

        # Start progress update
        self.update_progress()

    def update_progress(self):
        if not self.running:
            return
        if self.scanner:
            # Get current IP from queue (if any) – we can't easily get from scanner, but we can show count
            self.progress_var.set(f"Scanned: {self.scanner.processed_count} | Found: {self.scanner.found_count}")
            # Update found IPs list
            self.update_found_list()
        self.root.after(500, self.update_progress)

    def update_found_list(self):
        # Update treeview with found IPs
        if self.scanner:
            with self.scanner.lock:
                for ip, techs in self.scanner.found_ips.items():
                    # Check if already in tree (by IP)
                    exists = False
                    for child in self.tree.get_children():
                        if self.tree.item(child)['values'][0] == ip:
                            exists = True
                            break
                    if not exists:
                        self.tree.insert("", tk.END, values=(ip, ', '.join(techs)))
                        self.tree.yview_moveto(1.0)  # scroll to bottom

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
        self.running = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.progress_bar.stop()
        self.log("Stopped by user.")
        if self.scanner:
            self.progress_var.set(f"Scanned: {self.scanner.processed_count} | Found: {self.scanner.found_count}")
            self.log(f"Found {self.scanner.found_count} IPs.")
            self.log(f"Results saved in {self.scanner.output_file}")

    def on_closing(self):
        if self.running:
            self.stop_scan()
        self.root.destroy()


if __name__ == "__main__":
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    root = tk.Tk()
    app = ScannerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
