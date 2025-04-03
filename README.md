# ScanPy - Simple Port Scanner

A lightweight Python port scanner with multi-threading capabilities.

## Setup Instructions

### Setting up a Virtual Environment

1. Clone the repository:
```bash
git clone <repository-url>
cd tpe2
```

2. Create a virtual environment:
```bash
python -m venv venv
```

3. Activate the virtual environment:

On Windows:
```bash
venv\Scripts\activate
```

On macOS/Linux:
```bash
source venv/bin/activate
```

### Installing Dependencies

Install the required packages:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python main.py <target>
```

### Examples

Scan a single host with default settings (ports 1-1000):
```bash
python main.py 192.168.1.1
```

Scan specific ports:
```bash
python main.py example.com -p 80,443,8080
```

Scan a port range:
```bash
python main.py 10.0.0.1 -p 1-1000
```

Scan a network with CIDR notation:
```bash
python main.py 192.168.1.0/24 -p 22,80,443
```

Adjust thread count for faster scanning (use with caution):
```bash
python main.py 192.168.1.1 -p 1-1000 -t 200
```

### Command-line Options

- `target`: Target to scan (IP, hostname, or CIDR notation)
- `-p, --ports`: Port(s) to scan (e.g., 80,443,8000-8100). Default is 1-1000.
- `-t, --threads`: Number of threads to use. Default is 100.

## Notes

- Scanning without permission may be illegal in many jurisdictions
- Only use on systems you own or have explicit permission to scan
- Higher thread counts may improve speed but could impact network performance