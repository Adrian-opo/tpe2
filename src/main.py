#!/usr/bin/env python3
import socket
import argparse
import ipaddress
import threading
import time
from datetime import datetime

# Lista de portas padrões comumente utilizadas
STANDARD_PORTS = [
    20, 21,       # FTP
    22,          # SSH
    23,          # Telnet
    25, 587,     # SMTP
    53,          # DNS
    80, 443,     # HTTP/HTTPS
    110, 995,    # POP3
    143, 993,    # IMAP
    389, 636,    # LDAP
    445,         # SMB
    1433, 1434,  # MS SQL
    3306,        # MySQL
    3389,        # RDP
    5432,        # PostgreSQL
    8080, 8443   # HTTP alternativo
]

def scan_port(target, port, timeout=1):
    """Scan a single port on the target."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            return port, True, service
        return port, False, None
    except socket.error:
        return port, False, None

def scan_target(target, ports, threads=100):
    """Scan specified ports on a target."""
    open_ports = []
    thread_list = []
    lock = threading.Lock()
    
    def worker(port):
        result = scan_port(target, port)
        if result[1]:  # If port is open
            with lock:
                open_ports.append(result)
    
    # Create threads for scanning
    for port in ports:
        thread = threading.Thread(target=worker, args=(port,))
        thread_list.append(thread)
    
    # Start threads in batches to avoid overwhelming the system
    batch_size = threads
    for i in range(0, len(thread_list), batch_size):
        batch = thread_list[i:i+batch_size]
        for thread in batch:
            thread.start()
        for thread in batch:
            thread.join()
    
    return sorted(open_ports)

def is_host_up(host, timeout=1):
    """Check if host is up by attempting to connect to port 80."""
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, 80))
        s.close()
        return True
    except:
        # Try ICMP ping (requires root privileges)
        import subprocess
        import platform
        
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', host]
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def get_targets(target_spec):
    """Convert target specification to a list of targets."""
    try:
        # Check if it's an IP network
        network = ipaddress.ip_network(target_spec, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        # It's a single host
        return [target_spec]

def parse_port_range(port_range):
    """Parse port range specification (e.g., '80,443,8000-8100')."""
    ports = []
    ranges = port_range.split(',')
    for r in ranges:
        if '-' in r:
            start, end = map(int, r.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(r))
    return ports

def main():
    parser = argparse.ArgumentParser(description='Simple Nmap-like port scanner')
    parser.add_argument('target', help='Target to scan (IP, hostname, or CIDR notation)')
    parser.add_argument('-p', '--ports', default=None, help='Port(s) to scan (e.g., 80,443,8000-8100)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads to use')
    args = parser.parse_args()
    
    print(f"ScanPy 1.0 - Simple Port Scanner")
    print(f"Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Parse targets and ports
    targets = get_targets(args.target)
    
    # Use predefined standard ports if no ports are specified
    if args.ports is None:
        ports = STANDARD_PORTS
        print(f"No ports specified, using standard ports")
    else:
        ports = parse_port_range(args.ports)
    
    print(f"Scanning {len(targets)} hosts for {len(ports)} ports")
    
    # Scan each target
    for target in targets:
        try:
            # Resolve hostname if needed
            ip = socket.gethostbyname(target)
            print(f"\nScanning {target} ({ip})")
            
            if not is_host_up(ip):
                print(f"Host {target} appears to be down")
                continue
            
            print(f"Host {target} is up")
            
            start_time = time.time()
            results = scan_target(ip, ports, args.threads)
            scan_time = time.time() - start_time
            
            if results:
                print(f"\nOpen ports on {target} ({ip}):")
                print("PORT\tSTATE\tSERVICE")
                for port, is_open, service in results:
                    print(f"{port}/tcp\topen\t{service}")
                print(f"\n{len(results)} open ports found")
            else:
                print(f"No open ports found on {target}")
            
            print(f"Scan completed in {scan_time:.2f} seconds")
            
        except socket.gaierror:
            print(f"Could not resolve {target}")
    
    print(f"\nScan finished at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
