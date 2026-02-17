# this code will:
# 1 discorver the Host in the range of 192.168.0.1 to 192.168.0.49
# 2 scan which ports are open
# 3 know what kind of services are running on said host
# 4 find the OS system of the devices we find

# we want to return these values when code is done
alive_hosts = []
mac_table = {} 
results = []
# host discovery
for ip in range 192.168.0.1 to 192.168.0.49
#   send an ARP request

    if host reply:
    # add ip to alive_hosts
    # mac_table [ip] = reply.mac

if alive_hosts is empty:
    # alive_hosts are all ip in range
    # mac "unknown"


# port scanning 
for host in alive_hosts:
    open_ports = []
    for port in selected_ports:
        # try to connect using tcp
        # if connection works add it to open_ports

# hostname search 
try reverse DNS Lookup
if fail:
    hostname = "unkown"

# service dectection (using nmap -sV)
services = {}
if open_ports exist:
    detect service 

# OS dectection (using nmap -O)
OS = "unknown"
if open_ports exist:
    run os dectection

# save everything into results
end = {}
save following in end:
ip address
mac address
hostname
open_ports
services
OS
put end in results

print results and scan Stats

