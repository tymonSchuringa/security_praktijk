    for ip in targets:
        icmp_reply = srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=ip) / ICMP(),
            timeout=1,
            verbose=0
        )

        if icmp_reply:
            print("  ICMP worked")
            hit.append("ICMP")

            if icmp_reply.haslayer(Ether):
                dst_mac = icmp_reply[Ether].src
                if dst_mac == "00:00:00:00:00:00":
                    dst_mac = None
            else:
                dst_mac = None
        else:
            print("  ICMP failed")

        # TCP
        tcp_ports_worked = []

        if dst_mac:
            for port in [22, 80, 443]:
                tcp_reply = srp1(
                    Ether(dst=dst_mac) /
                    IP(dst=ip) /
                    TCP(dport=port, flags="S"),
                    timeout=1,
                    verbose=0
                )

                if tcp_reply:
                    tcp_ports_worked.append(port)

            if tcp_ports_worked:
                print(f"  TCP {tcp_ports_worked}")
                hit.append(f"TCP {tcp_ports_worked}")
            else:
                print("  TCP failed")
        else:
            print("  TCP skipped")

        # UDP
        if dst_mac:
            udp_reply = srp1(
                Ether(dst=dst_mac) / IP(dst=ip) / UDP(dport=161),
                timeout=1,
                verbose=0
            )
            if udp_reply:
                print("  UDP 161 worked")
                hit.append("UDP 161")
            else:
                print("  UDP 161 failed")
        else:
            print("  UDP skipped")

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


    if isinstance(alive_hosts, list):

        selected_ports = [
            22, 23, 53, 80, 123,
            161, 389, 443, 445,
            3389, 8080
        ]

        for host in alive_hosts:

            print(f"\n scanning host {host}...")

            # port scanner
            open_ports = []
            print("scanning ports...")
            for port in selected_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)

                try:
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        open_ports.append(port)
                except OSError:
                    pass
                finally:
                    sock.close()

            # detect hostname
            print("scanning for hostname...")
            try:
                hostname = socket.gethostbyaddr(host)[0]
            except Exception:
                hostname = "unknown"

            # detect services 
            services = {}
            print("scanning for services")
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

            # detect OS
            OS = "unknown"
            print("scanning most likely OS...")
            if open_ports:
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