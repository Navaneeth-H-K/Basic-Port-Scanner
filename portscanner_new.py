import argparse
import socket
import ssl
import concurrent.futures
import time
import json
import csv
from datetime import datetime

#Expand Ports
def expand_ports(ports_str):
    ports = []
    for part in ports_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

#Simple Fingerprint
def fingerprint_service(banner):
    if not banner:
        return None
    banner_lower = banner.lower()
    if "ssh" in banner_lower:
        return "SSH"
    if "http" in banner_lower:
        return "HTTP"
    if "ftp" in banner_lower:
        return "FTP"
    if "smtp" in banner_lower:
        return "SMTP"
    return "Unknown"

#Scanning TCP Port
def scan_tcp(host, port, timeout=1.0, tls=False, rate_limit=None):
    result = {
        "port": port,
        "protocol": "TCP",
        "status": "closed",
        "banner": None,
        "fingerprint": None,
        "rtt_ms": None,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    start = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            result["status"] = "open"

            if tls:  # Wrap TLS if chosen (e.g., port 443)
                context = ssl.create_default_context()
                with context.wrap_socket(s, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    result["banner"] = f"TLS handshake successful. Cert Subject: {cert.get('subject')}"
            else:
                s.settimeout(0.5)
                try:
                    banner = s.recv(1024).decode(errors="ignore").strip()
                    if not banner:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(1024).decode(errors="ignore").strip()
                    result["banner"] = banner
                except socket.timeout:
                    pass

            result["fingerprint"] = fingerprint_service(result["banner"])
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    finally:
        result["rtt_ms"] = round((time.time() - start) * 1000, 2)

    if rate_limit:
        time.sleep(rate_limit)
    return result

# Scan UDP Port
def scan_udp(host, port, timeout=1.0, rate_limit=None):
    result = {
        "port": port,
        "protocol": "UDP",
        "status": "closed/filtered",
        "banner": None,
        "fingerprint": None,
        "rtt_ms": None,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    start = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"", (host, port))
            data, _ = s.recvfrom(1024)
            result["status"] = "open"
            result["banner"] = data.decode(errors="ignore").strip()
            result["fingerprint"] = fingerprint_service(result["banner"])
    except socket.timeout:
        pass
    except OSError:
        pass
    finally:
        result["rtt_ms"] = round((time.time() - start) * 1000, 2)

    if rate_limit:
        time.sleep(rate_limit)
    return result


def main():
    parser = argparse.ArgumentParser(description="Extended Port Scanner")
    parser.add_argument("host", help="Host to scan (IP or domain)")
    parser.add_argument("ports", help="Ports to scan, e.g. 22,80,443 or 1-1024")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of worker threads")
    parser.add_argument("-o", "--output", help="Output file name (json or csv)")


    parser.add_argument("--udp", action="store_true", help="Enable UDP scanning")
    parser.add_argument("--tls", action="store_true", help="Use TLS handshake on TCP (like port 443)")
    parser.add_argument("--rate", type=float, default=0.0, help="Rate limit between scans (seconds)")

    args = parser.parse_args()

    ports = expand_ports(args.ports)
    results = []

    print(f"Scanning {args.host} on ports: {ports}")
    print(f"Mode: {'UDP' if args.udp else 'TCP'} | Threads: {args.threads}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for port in ports:
            if args.udp:
                futures.append(executor.submit(scan_udp, args.host, port, rate_limit=args.rate))
            else:
                futures.append(executor.submit(scan_tcp, args.host, port, tls=args.tls, rate_limit=args.rate))

        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            results.append(res)
            print(json.dumps(res))

    if args.output and results:
        if args.output.lower().endswith(".json"):
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
        elif args.output.lower().endswith(".csv"):
            with open(args.output, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
        print(f"Saved results to {args.output}")

if __name__ == "__main__":
    main()

