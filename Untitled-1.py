from scapy.all import ARP, Ether, srp1, conf

conf.verb = 0
conf.iface = "Ethernet"  # pas aan

ip = "192.168.68.102"
pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
ans = srp1(pkt, timeout=2, verbose=0)

print(ans.summary() if ans else "No ARP reply")