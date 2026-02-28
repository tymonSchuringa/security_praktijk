"""
Network Scanner - Ziyad & Tymon

Scans a single host or an IP range for reachability and gathers:
- MAC address (ARP when possible)
- Protocol hits (ARP/ICMP/TCP/UDP)
- Open TCP ports (connect scan)
- Hostname (reverse DNS if available)
- Service names (nmap -sV on open ports)
- OS guess (nmap -O)

Note: ARP only works within the same Layer-2 broadcast domain.
"""

from __future__ import annotations

from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, sr1, srp1, conf
import socket
import nmap

conf.verb = 0


# -----------------------------
# Input / target selection
# -----------------------------
def build_targets() -> list[str]:
    """Ask the user for scan mode and return a list of target IP addresses."""
    print("Hello! this is a network scanner by Ziyad and Tymon.\n")
    print("Would you like:")
    print("1. to scan a network? press 1")
    print("2. to scan a single host? press 2")
    print("3. to quit? press 3\n")

    try:
        choice = int(input("Choice: ").strip())
    except ValueError:
        print("Invalid choice (not a number). Exiting.")
        raise SystemExit(1)

    targets: list[str] = []

    if choice == 1:
        subnet_base = input("Please enter the subnet base (example: 192.168.0): ").strip()
        ran = input("Enter the range (example: 1-10): ").strip()

        parts = ran.split("-")
        if len(parts) != 2:
            print("Invalid range format. Use like 1-10.")
            raise SystemExit(1)

        start = int(parts[0])
        end = int(parts[1])

        for last in range(start, end + 1):
            targets.append(f"{subnet_base}.{last}")

    elif choice == 2:
        ip_addr = input("Please enter the host IP (example: 192.168.0.10): ").strip()
        targets.append(ip_addr)

    elif choice == 3:
        print("Ok.")
        raise SystemExit(0)

    else:
        print("Invalid choice. Exiting.")
        raise SystemExit(1)

    return targets


# -----------------------------
# Layer 2 / Layer 3 probes
# -----------------------------
def get_mac_via_arp(ip_addr: str, timeout: float = 1.0) -> str | None:
    """
    Try to obtain the target MAC address using ARP.

    Returns:
        MAC address string if found, otherwise None.
    """
    arp = ARP(pdst=ip_addr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    reply = srp1(packet, timeout=timeout, verbose=0)
    if reply and reply.haslayer(Ether):
        mac = reply[Ether].src
        if mac and mac != "00:00:00:00:00:00":
            return mac
    return None


def probe_icmp(ip_addr: str, timeout: float = 1.0) -> bool:
    """Return True if the host responds to an ICMP echo request."""
    reply = sr1(IP(dst=ip_addr) / ICMP(), timeout=timeout, verbose=0)
    return reply is not None


def probe_tcp_syn(ip_addr: str, port: int = 22, timeout: float = 1.0) -> bool:
    """
    Send a TCP SYN to the target port (Layer 3, no MAC required).

    Returns True if any response is received (SYN/ACK or RST).
    """
    reply = sr1(IP(dst=ip_addr) / TCP(dport=port, flags="S"), timeout=timeout, verbose=0)
    return reply is not None


def probe_udp(ip_addr: str, port: int = 161, timeout: float = 1.0) -> bool:
    """
    Send a UDP packet to the target port (Layer 3).

    UDP is tricky: lack of response doesn't always mean "down".
    We treat any response (UDP or ICMP) as a hit.
    """
    reply = sr1(IP(dst=ip_addr) / UDP(dport=port), timeout=timeout, verbose=0)
    return reply is not None


# -----------------------------
# Details collection
# -----------------------------
def tcp_connect_scan(ip_addr: str, ports: list[int], timeout: float = 0.3) -> list[int]:
    """Return a list of open TCP ports using a simple connect scan."""
    open_ports: list[int] = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip_addr, port))
        sock.close()

        if result == 0:
            open_ports.append(port)

    return open_ports


def resolve_hostname(ip_addr: str) -> str:
    """Resolve reverse DNS hostname; returns 'unknown' if not available."""
    try:
        return socket.gethostbyaddr(ip_addr)[0]
    except (socket.herror, socket.gaierror):
        return "unknown"


def detect_services(ip_addr: str, open_ports: list[int]) -> dict[int, str]:
    """Use nmap -sV to detect service names for the given open TCP ports."""
    if not open_ports:
        return {}

    try:
        nm = nmap.PortScanner()
        ports_string = ",".join(str(p) for p in open_ports)
        nm.scan(ip_addr, arguments=f"-sV -Pn -p {ports_string}")

        services: dict[int, str] = {}
        if ip_addr in nm.all_hosts() and "tcp" in nm[ip_addr]:
            for p in nm[ip_addr]["tcp"]:
                services[p] = nm[ip_addr]["tcp"][p].get("name", "unknown")
        return services
    except Exception:
        return {}


def detect_os(ip_addr: str) -> str:
    """Use nmap -O to guess the OS; returns 'unknown' on failure."""
    try:
        nm = nmap.PortScanner()
        nm.scan(ip_addr, arguments="-O -Pn")

        if ip_addr in nm.all_hosts():
            matches = nm[ip_addr].get("osmatch", [])
            if matches:
                return matches[0].get("name", "unknown")
        return "unknown"
    except Exception:
        return "unknown"


# -----------------------------
# Output formatting
# -----------------------------
def format_services(services: dict[int, str]) -> str:
    """Format services dict as '80:http, 443:https'."""
    if not services:
        return "unknown"
    items = [f"{p}:{services[p]}" for p in sorted(services)]
    return ", ".join(items)


def print_results_table(results: dict[str, dict]) -> None:
    """Print a clean table of results per host."""
    # Column headers
    header = (
        f"{'IP':<15}  {'MAC':<17}  {'Hostname':<25}  {'OS':<25}  "
        f"{'Open Ports':<20}  {'Services'}"
    )
    print("\nRESULTS")
    print(header)
    print("-" * len(header))

    for ip_addr, data in results.items():
        open_ports_str = ", ".join(str(p) for p in data["open_ports"]) if data["open_ports"] else "none"
        services_str = format_services(data["services"])
        print(
            f"{ip_addr:<15}  {data['mac']:<17}  {data['hostname']:<25}  {data['os']:<25}  "
            f"{open_ports_str:<20}  {services_str}"
        )


# -----------------------------
# Main flow
# -----------------------------
def main() -> None:
    """Run the scanner and print results."""
    targets = build_targets()

    alive_hosts: list[str] = []
    mac_table: dict[str, str] = {}
    protocol_hits: dict[str, list[str]] = {}
    results: dict[str, dict] = {}

    # First pass: host discovery via ARP/ICMP/TCP/UDP
    for ip_addr in targets:
        print(f"Scanning {ip_addr}...")
        hits: list[str] = []

        mac = get_mac_via_arp(ip_addr)
        if mac:
            print("  ARP worked")
            hits.append("ARP")
        else:
            mac = "unknown"

        if probe_icmp(ip_addr):
            print("  ICMP responded")
            hits.append("ICMP")
        else:
            print("  ICMP failed")

        if probe_tcp_syn(ip_addr, port=22):
            print("  TCP responded")
            hits.append("TCP")
        else:
            print("  TCP failed")

        if probe_udp(ip_addr, port=161):
            print("  UDP responded")
            hits.append("UDP")
        else:
            print("  UDP failed")

        if hits:
            alive_hosts.append(ip_addr)
            mac_table[ip_addr] = mac
            protocol_hits[ip_addr] = hits

    print("\nScan complete")

    if not alive_hosts:
        print("No hosts found")
        return

    # Optional quick summary (keep it short)
    for host in alive_hosts:
        print(f"{host} | MAC: {mac_table[host]} | Protocols: {protocol_hits[host]}")

    # Second pass: detailed scanning
    selected_ports = [22, 23, 53, 80, 123, 161, 389, 443, 445, 3389, 8080]

    for host in alive_hosts:
        print(f"\nScanning details for {host}...")

        open_ports = tcp_connect_scan(host, selected_ports, timeout=0.3)
        hostname = resolve_hostname(host)
        services = detect_services(host, open_ports)
        os_name = detect_os(host)

        results[host] = {
            "mac": mac_table[host],
            "hostname": hostname,
            "open_ports": open_ports,
            "services": services,
            "os": os_name,
        }

    print_results_table(results)


if __name__ == "__main__":
    main()