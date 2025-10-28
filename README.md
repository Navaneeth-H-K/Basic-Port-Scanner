# Basic-Port-Scanner
PyPortScanner A fast, multi-threaded TCP/UDP port scanner in Python with banner grabbing, TLS support, and flexible output (JSON/CSV).

## 📋 Requirements - Python 3.11 or above



## ⚙️ Usage

Save the script as `port_scanner.py` and run it from the command line.


python port_scanner.py -h
usage: port_scanner.py [-h] [-t THREADS] [-o OUTPUT] [--udp] [--tls] [--rate RATE] host ports

Extended Port Scanner

positional arguments:
  host                  Host to scan (IP or domain)
  ports                 Ports to scan, e.g. 22,80,443 or 1-1024

options:
  -h, --help            show this help message and exit
  -t THREADS, --threads THREADS
                        Number of worker threads (default: 50)
  -o OUTPUT, --output OUTPUT
                        Output file name (json or csv)
  --udp                 Enable UDP scanning
  --tls                 Use TLS handshake on TCP (like port 443)
  --rate RATE           Rate limit between scans (seconds) (default: 0.0)
