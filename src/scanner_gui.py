#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import ipaddress
import subprocess
import platform
import netifaces
import time
from main import scan_target, parse_port_range

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Port Scanner")
        self.root.geometry("900x700")
        
        # Set theme - try to use a more modern theme if available
        try:
            self.root.tk.call("source", "azure.tcl")
            self.root.tk.call("set_theme", "light")
        except:
            pass
        
        # Variables
        self.hosts = []
        self.scan_types = {
            "Quick Scan": "80,443",
            "Common Ports": "20-22,25,53,80,110,139,443,445,3306,3389,8080",
            "Comprehensive": "1-1024",
            "Full Scan": "1-65535",
            "Custom": "",
        }
        
        # Create menu
        self.create_menu()
        self.create_widgets()
        
        # Automatically discover hosts on startup
        self.root.after(500, self.scan_subnet)
    
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Discover Hosts", command=self.scan_subnet)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Scan Menu
        scan_menu = tk.Menu(menubar, tearoff=0)
        scan_menu.add_command(label="Scan Selected Host", command=self.scan_selected_host)
        scan_menu.add_command(label="Scan All Hosts", command=self.scan_all_hosts)
        menubar.add_cascade(label="Scan", menu=scan_menu)
        
        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Help", command=self.show_help)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
        
    def create_widgets(self):
        # Main frame with notebook for tabs
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook with tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Scanner tab
        scanner_frame = ttk.Frame(notebook, padding="5")
        notebook.add(scanner_frame, text="Network Scanner")
        
        # Reports tab
        reports_frame = ttk.Frame(notebook, padding="5")
        notebook.add(reports_frame, text="Reports")
        
        # Setup Scanner tab content
        self.setup_scanner_tab(scanner_frame)
        
        # Setup Reports tab content
        self.setup_reports_tab(reports_frame)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Progress bar
        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, mode='indeterminate')
        self.progress.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_scanner_tab(self, parent):
        # Split frame into two panels
        paned = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Hosts list
        left_frame = ttk.LabelFrame(paned, text="Network Hosts", padding="5")
        paned.add(left_frame, weight=1)
        
        # Scan subnet section
        scan_subnet_frame = ttk.Frame(left_frame)
        scan_subnet_frame.pack(fill=tk.X, pady=5)
        
        self.subnet_var = tk.StringVar()
        self.subnet_var.set(self.get_default_subnet())
        ttk.Label(scan_subnet_frame, text="Network:").pack(side=tk.LEFT, padx=5)
        subnet_entry = ttk.Entry(scan_subnet_frame, textvariable=self.subnet_var, width=20)
        subnet_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        scan_subnet_btn = ttk.Button(scan_subnet_frame, text="Discover Hosts", command=self.scan_subnet)
        scan_subnet_btn.pack(side=tk.RIGHT, padx=5)
        
        # Hosts tree view with context menu
        hosts_frame = ttk.Frame(left_frame)
        hosts_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create columns for the treeview
        columns = ("ip", "hostname", "status")
        self.hosts_tree = ttk.Treeview(hosts_frame, columns=columns, show="headings", selectmode="extended")
        self.hosts_tree.heading("ip", text="IP Address")
        self.hosts_tree.heading("hostname", text="Hostname")
        self.hosts_tree.heading("status", text="Status")
        
        self.hosts_tree.column("ip", width=120)
        self.hosts_tree.column("hostname", width=180)
        self.hosts_tree.column("status", width=80)
        
        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(hosts_frame, orient=tk.VERTICAL, command=self.hosts_tree.yview)
        self.hosts_tree.configure(yscroll=y_scrollbar.set)
        
        # Pack the treeview and scrollbar
        self.hosts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add right-click context menu to the hosts tree
        self.create_context_menu()
        
        # Right panel - Scan options and results
        right_paned = ttk.PanedWindow(paned, orient=tk.VERTICAL)
        paned.add(right_paned, weight=1)
        
        # Scan options frame
        options_frame = ttk.LabelFrame(right_paned, text="Scan Options", padding="5")
        right_paned.add(options_frame, weight=1)
        
        # Scan type selection
        ttk.Label(options_frame, text="Scan Type:").pack(anchor=tk.W, pady=(10, 5))
        self.scan_type_var = tk.StringVar()
        self.scan_type_var.set(list(self.scan_types.keys())[0])
        
        scan_types_frame = ttk.Frame(options_frame)
        scan_types_frame.pack(fill=tk.X, padx=10, pady=5)
        
        for i, scan_type in enumerate(self.scan_types.keys()):
            ttk.Radiobutton(scan_types_frame, text=scan_type, value=scan_type, 
                           variable=self.scan_type_var, command=self.update_custom_ports).grid(
                               row=i//2, column=i%2, sticky=tk.W, padx=5, pady=2)
        
        # Custom port range
        port_frame = ttk.LabelFrame(options_frame, text="Port Configuration", padding="5")
        port_frame.pack(fill=tk.X, padx=10, pady=10, ipady=5)
        
        ttk.Label(port_frame, text="Custom Port Range:").pack(anchor=tk.W, pady=(5, 5))
        self.custom_ports_var = tk.StringVar()
        port_entry = ttk.Entry(port_frame, textvariable=self.custom_ports_var)
        port_entry.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(port_frame, text="Example: 80,443,8000-8100").pack(anchor=tk.W, padx=5)
        
        # Threads configuration
        self.threads_var = tk.IntVar(value=100)
        threads_frame = ttk.Frame(options_frame)
        threads_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(threads_frame, text="Threads:").pack(side=tk.LEFT, padx=5)
        threads_spinbox = ttk.Spinbox(threads_frame, from_=1, to=500, textvariable=self.threads_var, width=5)
        threads_spinbox.pack(side=tk.LEFT, padx=5)
        
        # Action buttons
        buttons_frame = ttk.Frame(options_frame)
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        
        scan_btn = ttk.Button(buttons_frame, text="Scan Selected Host", 
                             command=self.scan_selected_host)
        scan_btn.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        scan_all_btn = ttk.Button(buttons_frame, text="Scan All Hosts", 
                                 command=self.scan_all_hosts)
        scan_all_btn.pack(side=tk.RIGHT, padx=5, fill=tk.X, expand=True)
        
        # Results frame
        results_frame = ttk.LabelFrame(right_paned, text="Scan Results", padding="5")
        right_paned.add(results_frame, weight=2)
        
        # Results text area with scrollbars
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, width=60, height=15)
        self.results_text.pack(fill=tk.BOTH, expand=True, pady=5)
    
    def setup_reports_tab(self, parent):
        # Reports tab content
        ttk.Label(parent, text="Saved Scan Reports").pack(anchor=tk.W, pady=(10, 5))
        
        # Reports list
        self.reports_tree = ttk.Treeview(parent, columns=("date", "target", "ports"), show="headings")
        self.reports_tree.heading("date", text="Date")
        self.reports_tree.heading("target", text="Target(s)")
        self.reports_tree.heading("ports", text="Open Ports")
        
        self.reports_tree.column("date", width=150)
        self.reports_tree.column("target", width=200)
        self.reports_tree.column("ports", width=400)
        
        self.reports_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Buttons for reports
        buttons_frame = ttk.Frame(parent)
        buttons_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(buttons_frame, text="View Report", command=self.view_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Export Report", command=self.export_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Delete Report", command=self.delete_report).pack(side=tk.LEFT, padx=5)
    
    def create_context_menu(self):
        # Create context menu for right-click on hosts
        self.host_menu = tk.Menu(self.root, tearoff=0)
        self.host_menu.add_command(label="Scan Host", command=self.scan_selected_host)
        self.host_menu.add_command(label="Ping Host", command=self.ping_host)
        self.host_menu.add_separator()
        self.host_menu.add_command(label="Copy IP", command=lambda: self.copy_to_clipboard("ip"))
        self.host_menu.add_command(label="Copy Hostname", command=lambda: self.copy_to_clipboard("hostname"))
        
        # Bind right-click to show context menu
        self.hosts_tree.bind("<Button-3>", self.show_context_menu)
    
    def show_context_menu(self, event):
        try:
            item = self.hosts_tree.identify_row(event.y)
            if item:
                self.hosts_tree.selection_set(item)
                self.host_menu.post(event.x_root, event.y_root)
        finally:
            self.host_menu.grab_release()
    
    def copy_to_clipboard(self, column):
        selected = self.hosts_tree.selection()
        if not selected:
            return
        
        item = self.hosts_tree.item(selected[0])
        column_idx = {"ip": 0, "hostname": 1, "status": 2}
        value = item['values'][column_idx.get(column, 0)]
        
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.status_var.set(f"Copied {column}: {value}")
    
    def get_default_subnet(self):
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][1]
            
            # Get the address information for that interface
            addrs = netifaces.ifaddresses(default_gateway)
            ip_info = addrs[netifaces.AF_INET][0]
            
            ip = ip_info['addr']
            netmask = ip_info['netmask']
            
            # Calculate the network address
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
        except:
            return "192.168.1.0/24"  # Fallback to common LAN subnet
    
    def is_host_up(self, host, timeout=1):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W', str(timeout), host]
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    
    def get_hostname(self, ip):
        try:
            return socket.getfqdn(ip)
        except:
            return "Unknown"
    
    def update_custom_ports(self):
        scan_type = self.scan_type_var.get()
        if scan_type == "Custom":
            self.custom_ports_var.set("")
        else:
            self.custom_ports_var.set(self.scan_types.get(scan_type, ""))
    
    def scan_subnet(self):
        subnet = self.subnet_var.get()
        self.hosts_tree.delete(*self.hosts_tree.get_children())
        self.status_var.set(f"Discovering hosts on {subnet}...")
        self.hosts = []
        
        # Start progress bar
        self.progress.start()
        
        def scan_worker():
            try:
                network = ipaddress.ip_network(subnet, strict=False)
                total_hosts = network.num_addresses - 2  # Exclude network and broadcast addresses
                
                for i, ip in enumerate(network.hosts()):
                    ip_str = str(ip)
                    if self.is_host_up(ip_str):
                        hostname = self.get_hostname(ip_str)
                        self.hosts.append((ip_str, hostname, "Up"))
                        self.hosts_tree.insert("", "end", values=(ip_str, hostname, "Up"))
                    
                    # Update status every 10 hosts
                    if i % 10 == 0:
                        self.status_var.set(f"Scanning: {i}/{total_hosts} hosts checked...")
                        self.root.update_idletasks()
                
                if len(self.hosts) == 0:
                    messagebox.showinfo("Scan Complete", "No active hosts found on the network.")
                else:
                    self.status_var.set(f"Found {len(self.hosts)} active hosts")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {str(e)}")
                self.status_var.set("Ready")
            finally:
                # Stop progress bar
                self.progress.stop()
        
        # Run the scan in a separate thread to keep the UI responsive
        threading.Thread(target=scan_worker, daemon=True).start()
    
    def scan_selected_host(self):
        selected = self.hosts_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a host to scan.")
            return
        
        item = self.hosts_tree.item(selected[0])
        ip = item['values'][0]
        hostname = item['values'][1]
        
        # Determine port range
        scan_type = self.scan_type_var.get()
        if scan_type == "Custom" or self.custom_ports_var.get():
            ports_str = self.custom_ports_var.get()
        else:
            ports_str = self.scan_types[scan_type]
        
        self.status_var.set(f"Scanning {ip} ({scan_type})...")
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Scanning {ip} ({hostname}) - {scan_type} scan\n")
        self.results_text.insert(tk.END, f"Port range: {ports_str}\n\n")
        
        # Start progress bar
        self.progress.start()
        
        def scan_worker():
            try:
                start_time = time.time()
                ports = parse_port_range(ports_str)
                self.results_text.insert(tk.END, f"Scanning {len(ports)} ports...\n")
                
                threads = self.threads_var.get()
                results = scan_target(ip, ports, threads)
                
                scan_time = time.time() - start_time
                
                if results:
                    self.results_text.insert(tk.END, "\nOpen ports:\n")
                    self.results_text.insert(tk.END, "PORT\tSTATE\tSERVICE\n")
                    self.results_text.insert(tk.END, "-" * 40 + "\n")
                    
                    for port, is_open, service in results:
                        self.results_text.insert(tk.END, f"{port}/tcp\topen\t{service}\n")
                    
                    self.results_text.insert(tk.END, f"\n{len(results)} open ports found\n")
                    self.results_text.insert(tk.END, f"Scan completed in {scan_time:.2f} seconds\n")
                    
                    # Add to reports
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    port_list = ", ".join([f"{port[0]}/{port[2]}" for port in results])
                    self.reports_tree.insert("", 0, values=(timestamp, f"{ip} ({hostname})", port_list))
                else:
                    self.results_text.insert(tk.END, "\nNo open ports found\n")
                    self.results_text.insert(tk.END, f"Scan completed in {scan_time:.2f} seconds\n")
                
                self.status_var.set(f"Scan completed: {ip}")
            except Exception as e:
                self.results_text.insert(tk.END, f"\nError during scan: {str(e)}\n")
                self.status_var.set("Scan error")
            finally:
                # Stop progress bar
                self.progress.stop()
        
        # Run the scan in a separate thread
        threading.Thread(target=scan_worker, daemon=True).start()
    
    def scan_all_hosts(self):
        """Scan all discovered hosts"""
        if not self.hosts:
            messagebox.showinfo("No Hosts", "No hosts to scan. Please discover hosts first.")
            return
        
        # Confirm before scanning multiple hosts
        if len(self.hosts) > 5:
            if not messagebox.askyesno("Confirm", f"Are you sure you want to scan all {len(self.hosts)} hosts? This may take a while."):
                return
        
        # Clear results and start scanning each host
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Starting scan of {len(self.hosts)} hosts\n\n")
        
        # Get scan configuration
        scan_type = self.scan_type_var.get()
        if scan_type == "Custom" or self.custom_ports_var.get():
            ports_str = self.custom_ports_var.get()
        else:
            ports_str = self.scan_types[scan_type]
        
        threads = self.threads_var.get()
        
        # Start progress bar
        self.progress.start()
        
        def scan_all_worker():
            try:
                start_time = time.time()
                ports = parse_port_range(ports_str)
                
                hosts_with_open_ports = 0
                total_open_ports = 0
                
                for i, (ip, hostname, _) in enumerate(self.hosts):
                    self.status_var.set(f"Scanning host {i+1}/{len(self.hosts)}: {ip}")
                    self.results_text.insert(tk.END, f"Scanning {ip} ({hostname})...\n")
                    self.root.update_idletasks()
                    
                    try:
                        results = scan_target(ip, ports, threads)
                        
                        if results:
                            hosts_with_open_ports += 1
                            total_open_ports += len(results)
                            
                            self.results_text.insert(tk.END, f"Found {len(results)} open ports:\n")
                            for port, _, service in results:
                                self.results_text.insert(tk.END, f"  {port}/tcp ({service})\n")
                            
                            # Add to reports
                            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                            port_list = ", ".join([f"{port[0]}/{port[2]}" for port in results])
                            self.reports_tree.insert("", 0, values=(timestamp, f"{ip} ({hostname})", port_list))
                        else:
                            self.results_text.insert(tk.END, "No open ports found\n")
                        
                        self.results_text.insert(tk.END, "\n")
                    except Exception as e:
                        self.results_text.insert(tk.END, f"Error scanning {ip}: {str(e)}\n\n")
                
                total_time = time.time() - start_time
                self.results_text.insert(tk.END, f"\nScan Summary:\n")
                self.results_text.insert(tk.END, f"Scanned {len(self.hosts)} hosts\n")
                self.results_text.insert(tk.END, f"Found {total_open_ports} open ports on {hosts_with_open_ports} hosts\n")
                self.results_text.insert(tk.END, f"Total scan time: {total_time:.2f} seconds\n")
                
                self.status_var.set(f"Completed scanning {len(self.hosts)} hosts")
            except Exception as e:
                self.results_text.insert(tk.END, f"\nError during scan: {str(e)}\n")
                self.status_var.set("Scan error")
            finally:
                self.progress.stop()
        
        # Run the scan in a separate thread
        threading.Thread(target=scan_all_worker, daemon=True).start()
    
    def ping_host(self):
        """Ping the selected host and show results"""
        selected = self.hosts_tree.selection()
        if not selected:
            return
        
        item = self.hosts_tree.item(selected[0])
        ip = item['values'][0]
        
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Pinging {ip}...\n\n")
        
        def ping_worker():
            try:
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                command = ['ping', param, '4', ip]
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                output, error = process.communicate()
                
                if error:
                    self.results_text.insert(tk.END, f"Error: {error}\n")
                else:
                    self.results_text.insert(tk.END, output)
                
                self.status_var.set(f"Finished pinging {ip}")
            except Exception as e:
                self.results_text.insert(tk.END, f"Error: {str(e)}\n")
                self.status_var.set("Ping error")
        
        threading.Thread(target=ping_worker, daemon=True).start()
    
    def view_report(self):
        """View a saved report"""
        selected = self.reports_tree.selection()
        if not selected:
            messagebox.showinfo("No Selection", "Please select a report to view.")
            return
        
        item = self.reports_tree.item(selected[0])
        date, target, ports = item['values']
        
        # Create a report view window
        report_window = tk.Toplevel(self.root)
        report_window.title(f"Report: {target}")
        report_window.geometry("500x400")
        
        report_text = scrolledtext.ScrolledText(report_window, wrap=tk.WORD)
        report_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        report_text.insert(tk.END, f"Scan Report - {date}\n")
        report_text.insert(tk.END, f"Target: {target}\n\n")
        report_text.insert(tk.END, "Open Ports:\n")
        
        for port in ports.split(", "):
            report_text.insert(tk.END, f"  {port}\n")
    
    def export_report(self):
        """Export a report to a file"""
        selected = self.reports_tree.selection()
        if not selected:
            messagebox.showinfo("No Selection", "Please select a report to export.")
            return
        
        item = self.reports_tree.item(selected[0])
        date, target, ports = item['values']
        
        from tkinter import filedialog
        import os
        
        # Create reports directory if it doesn't exist
        reports_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"scan_report_{target.split()[0]}_{date.replace(':', '-').replace(' ', '_')}.txt",
            initialdir=reports_dir
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(f"Scan Report - {date}\n")
                    f.write(f"Target: {target}\n\n")
                    f.write("Open Ports:\n")
                    for port in ports.split(", "):
                        f.write(f"  {port}\n")
                messagebox.showinfo("Export Successful", f"Report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Failed", f"Failed to export report: {str(e)}")
    
    def delete_report(self):
        """Delete a report from the list"""
        selected = self.reports_tree.selection()
        if not selected:
            return
        
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this report?"):
            self.reports_tree.delete(selected)
    
    def show_about(self):
        """Show about dialog"""
        about_text = """Network Port Scanner v1.0
        
A simple tool for discovering hosts and scanning ports on your network.

Features:
- Host discovery
- Port scanning with different scan types
- Reporting and exporting results
"""
        messagebox.showinfo("About", about_text)
    
    def show_help(self):
        """Show help information"""
        help_text = """Network Scanner Help
        
1. Discover Hosts:
   - Enter a subnet in CIDR notation (e.g., 192.168.1.0/24)
   - Click "Discover Hosts" to find active hosts

2. Scan Ports:
   - Select a host from the list
   - Choose a scan type or enter custom port range
   - Click "Scan Selected Host" to start scanning

3. View Results:
   - Open ports will be displayed in the results area
   - Reports are saved in the Reports tab
"""
        help_window = tk.Toplevel(self.root)
        help_window.title("Help")
        help_window.geometry("500x400")
        
        help_text_widget = scrolledtext.ScrolledText(help_window, wrap=tk.WORD)
        help_text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        help_text_widget.insert(tk.END, help_text)
        help_text_widget.configure(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()
