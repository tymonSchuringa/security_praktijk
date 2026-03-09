from scapy.all import ARP, Ether, srp, conf
from scapy.all import conf, get_if_list, get_if_addr

conf.verb = 0
MY_IP = "192.168.68.102"

conf.iface = None
for iface in get_if_list():
    try:
        if get_if_addr(iface) == MY_IP:
            conf.iface = iface
            break
    except Exception:
        pass

if not conf.iface:
    raise RuntimeError(f"Kon geen interface vinden met IP {MY_IP}")

print("Using interface:", conf.iface)

network = "192.168.68.0/24"

print(f"Scanning network {network}...\n")

arp = ARP(pdst=network)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether / arp

answered, unanswered = srp(packet, timeout=2, retry=1, verbose=0)

alive_hosts = []

for sent, received in answered:
    ip = received.psrc
    mac = received.hwsrc
    alive_hosts.append((ip, mac))
    print(f"Host found: {ip} | MAC: {mac}")

print(f"\nTotal hosts found: {len(alive_hosts)}")