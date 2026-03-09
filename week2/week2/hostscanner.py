"""
network scanner by Ziyad & Tymon

this code does the following:
- host discovery using ARP, ICMP, TCP and UDP probes
- TCP port scanning (connect scan)
- service detection using nmap (-sV)
- OS detection using nmap (-O)
- hostname lookup using reverse DNS

Note:
ARP scanning only works inside the same local network with a LAN connection.
Some hosts may block ICMP or certain probes.
"""

from scapy.all import Ether, IP, ICMP, TCP, UDP, ARP, sr1, srp1, conf
import socket
import nmap
conf.verb = 0

alive_hosts = []
mac_table = {}
protocol_hit = {}
results = {}
print("Hello! this is a network scanner by Ziyad & Tymon.\n")
print("Would you like:")
print("1. to scan a network? press 1")
print("2. to scan a single host? press 2")
print("3. to quit? press 3\n")



# menu, a choice to select your own network
try:
    choice = int(input("Choice: "))
except ValueError:
    print("thats not what i asked")
    exit()
targets = []

if choice == 1:

    subnet_base = input("Please enter the subnet base (example: 192.168.0): ")
    ran = input("Enter the range (example: 1-10): ")
    parts = ran.split("-")
    if len(parts) != 2:
        print("invalid range")
        exit()

    start = int(parts[0])
    end = int(parts[1])

    for last in range(start, end + 1):
        targets.append(subnet_base + "." + str(last))

elif choice == 2:

    ip = input("Please enter the host IP (example: 192.168.0.10): ")
    targets.append(ip)

else:
    print("ok.")
    exit()

for ip in targets:
    print(f"Scanning {ip}...")

    hit = []
    dst_mac = None

    # ARP request using scapy + retrieve MAC address
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    arp_reply = srp1(
        packet,
        timeout=1,
        verbose=0
    )

    if arp_reply and arp_reply.haslayer(Ether):
        dst_mac = arp_reply[Ether].src
        if dst_mac == "00:00:00:00:00:00":
            dst_mac = None
        else:
            hit.append("ARP")
            print("  ARP worked")

    # ICMP with scapy
    icmp_reply = sr1(
        IP(dst=ip) / ICMP(),
        timeout=1,
        verbose=0
    )

    if icmp_reply:
        print("  ICMP responded")
        hit.append("ICMP")
    else:
        print("  ICMP failed")

    # TCP only try when a MAC address has been found, so it can reach the host
    if dst_mac:
        tcp_reply = srp1(
            Ether(dst=dst_mac) /
            IP(dst=ip) /
            TCP(dport=22, flags="S"),
            timeout=1,
            verbose=0
        )
        if tcp_reply:
            print("   TCP responded")
            hit.append("TCP")
        else:
            print("  TCP failed")
    else:
        print("  TCP skipped (no MAC)")

    # UDP same logic as TCP 
    if dst_mac:
        udp_reply = srp1(
            Ether(dst=dst_mac) / IP(dst=ip) / UDP(dport=161),
            timeout=1,
            verbose=0
        )
        if udp_reply:
            print("  UDP responded")
            hit.append("UDP")
        else:
            print("  UDP failed")
    else:
        print("  UDP skipped (no MAC)")

    # save results
    if hit:
        alive_hosts.append(ip)
        protocol_hit[ip] = hit
        mac_table[ip] = dst_mac if dst_mac else "unknown"
# summary 
print("\nScan complete")

if len(alive_hosts) == 0:
    print("No hosts found")
else:
    for host in alive_hosts:
        print(f"{host} | MAC: {mac_table[host]} | Protocols: {protocol_hit[host]}")


    selected_ports = [22, 23, 53, 80, 123, 161, 389, 443, 445, 3389, 8080]
if len(alive_hosts) > 0:
    for host in alive_hosts:

        print(f"\n scanning host {host}...")

        # port scanner
        open_ports = []
        print("scanning ports...")

        for port in selected_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)

            result = sock.connect_ex((host, port))

            if result == 0:
                open_ports.append(port)

            sock.close()

        # detect hostname
        print("scanning for hostname...")
        try:
            hostname = socket.gethostbyaddr(host)[0]
        except socket.herror:
            hostname = "unknown"

        # detect services 
        services = {}
        print("scanning for services...")
        if open_ports:
            try:
                nm = nmap.PortScanner()
                ports_string = ",".join(str(p) for p in open_ports)

                nm.scan(host, arguments=f"-sV -Pn -p {ports_string}")

                if host in nm.all_hosts() and "tcp" in nm[host]:
                    for p in nm[host]["tcp"]:
                        services[p] = nm[host]["tcp"][p].get("name", "unknown")
            except Exception:
                services = {}

        # detect OS it will guess and can be incorrect
        OS = "unknown"
        print("scanning most likely OS...")
        try:
            nm = nmap.PortScanner()
            nm.scan(host, arguments="-O -Pn")

            if host in nm.all_hosts():
                if "osmatch" in nm[host] and nm[host]["osmatch"]:
                    OS = nm[host]["osmatch"][0].get("name", "unknown")
        except Exception:
            OS = "unknown"

        # save per host
        results[host] = {
            "open_ports": open_ports,
            "services": services,
            "OS": OS,
            "hostname": hostname
            }

    # results
    print("\n results")
    for host, data in results.items():
        print("---------------------")
        print("Host:", host)
        print("Hostname:", data["hostname"])
        print("Open ports:", data["open_ports"])
        print("Services:", data["services"])
        print("OS:", data["OS"])