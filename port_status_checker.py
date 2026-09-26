#!/usr/bin/env python3
"""
Port Status Checker
--------------------
Network socket utility that scans a target host over a given port range,
attempts a TCP connection handshake with a configurable timeout, and
reports each port's status as Open, Closed, or Filtered.

IMPORTANT / ETHICAL USE NOTICE:
Only scan hosts you own or have explicit written permission to test
(e.g. localhost, your own lab VM, or a host your organization has
authorized). Scanning third-party systems without permission may be
illegal in many jurisdictions.

Usage:
    python port_status_checker.py --host 127.0.0.1 --start 1 --end 1024
    python port_status_checker.py --host scanme.example.com --ports 22,80,443
    python port_status_checker.py --host 127.0.0.1 --start 1 --end 100 --timeout 0.5 --threads 50
"""

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# A small map of well-known ports -> service name, for readable output.
COMMON_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCBIND", 135: "MSRPC",
    139: "NETBIOS-SSN", 143: "IMAP", 443: "HTTPS", 445: "MICROSOFT-DS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MYSQL",
    3389: "RDP", 5432: "POSTGRESQL", 5900: "VNC", 6379: "REDIS",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MONGODB",
}


def service_name(port: int) -> str:
    return COMMON_SERVICES.get(port, "unknown")


def check_port(host: str, port: int, timeout: float) -> dict:
    """
    Attempt a TCP connect() handshake to (host, port).

    Returns a dict with status classified as:
      - "Open"     : connection succeeded (SYN/ACK handshake completed)
      - "Closed"   : connection actively refused (RST received)
      - "Filtered" : timed out / no response (likely firewall dropping packets)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.time()
    status = "Closed"
    try:
        result = sock.connect_ex((host, port))
        elapsed_ms = (time.time() - start) * 1000
        if result == 0:
            status = "Open"
        else:
            # ECONNREFUSED (10061 on Windows, 111 on Linux) -> actively closed
            # Other non-zero codes without a timeout are treated as closed too
            status = "Closed"
    except socket.timeout:
        elapsed_ms = timeout * 1000
        status = "Filtered"
    except socket.gaierror:
        raise
    except OSError:
        elapsed_ms = (time.time() - start) * 1000
        status = "Filtered"
    finally:
        sock.close()

    return {
        "port": port,
        "service": service_name(port),
        "status": status,
        "response_ms": round(elapsed_ms, 2),
    }


def scan_ports(host: str, ports: list, timeout: float, max_threads: int) -> list:
    results = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check_port, host, p, timeout): p for p in ports}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                port = futures[future]
                results.append({
                    "port": port,
                    "service": service_name(port),
                    "status": f"Error: {e}",
                    "response_ms": 0,
                })
    results.sort(key=lambda r: r["port"])
    return results


def print_table(host: str, results: list, elapsed_total: float):
    print("=" * 70)
    print(f" Port Status Report for host: {host}")
    print("=" * 70)
    print(f" {'PORT':<8}{'SERVICE':<15}{'STATUS':<12}{'RESPONSE (ms)':<15}")
    print("-" * 70)
    for r in results:
        print(f" {r['port']:<8}{r['service']:<15}{r['status']:<12}{r['response_ms']:<15}")
    print("-" * 70)

    open_count = sum(1 for r in results if r["status"] == "Open")
    closed_count = sum(1 for r in results if r["status"] == "Closed")
    filtered_count = sum(1 for r in results if r["status"] == "Filtered")

    print(f" Total scanned : {len(results)}")
    print(f" Open          : {open_count}")
    print(f" Closed        : {closed_count}")
    print(f" Filtered      : {filtered_count}")
    print(f" Scan duration : {elapsed_total:.2f} seconds")
    print("=" * 70)
    print()


def parse_port_arg(port_str: str) -> list:
    """Parse a comma-separated port list like '22,80,443'."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if part:
            ports.append(int(part))
    return ports


def main():
    parser = argparse.ArgumentParser(description="TCP Port Status Checker (Open/Closed/Filtered)")
    parser.add_argument("--host", required=True, help="Target host (IP address or hostname). Only scan hosts you own or are authorized to test.")
    parser.add_argument("--start", type=int, help="Start of port range (used with --end)")
    parser.add_argument("--end", type=int, help="End of port range (used with --start)")
    parser.add_argument("--ports", type=str, help="Comma-separated explicit port list, e.g. 22,80,443")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds per port (default: 1.0)")
    parser.add_argument("--threads", type=int, default=100, help="Max concurrent threads (default: 100)")
    args = parser.parse_args()

    if args.ports:
        ports = parse_port_arg(args.ports)
    elif args.start is not None and args.end is not None:
        ports = list(range(args.start, args.end + 1))
    else:
        # Default: common well-known ports
        ports = sorted(COMMON_SERVICES.keys())

    try:
        socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"Error: could not resolve host '{args.host}'. Check the hostname/IP and try again.")
        sys.exit(1)

    print(f"Scanning {args.host} across {len(ports)} port(s) with {args.timeout}s timeout...\n")
    start_time = time.time()
    results = scan_ports(args.host, ports, args.timeout, args.threads)
    elapsed_total = time.time() - start_time

    print_table(args.host, results, elapsed_total)


if __name__ == "__main__":
    main()
