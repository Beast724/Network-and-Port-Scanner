import socket
from scapy.all import sr1, IP, ICMP
import ipaddress

def is_host_live(host):
    """
    Check if a host is live by sending an ICMP ping request.
    """
    try:
        packet = IP(dst=host)/ICMP()
        response = sr1(packet, timeout=2, verbose=False)
        if response:
            return True
        else:
            return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def scan_ports(host, ports):
    """
    Scan a list of ports on a given host to determine if they are open or closed.
    """
    open_ports = []
    closed_ports = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 1 second timeout
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        else:
            closed_ports.append(port)
        sock.close()

    return open_ports, closed_ports

if __name__ == "__main__":
    start_ip = input("Enter the starting IP address: ")
    end_ip = input("Enter the ending IP address: ")
    ports = input("Enter the ports to scan (comma-separated): ")
    ports = [int(port.strip()) for port in ports.split(',')]

    try:
        start_ip = ipaddress.ip_address(start_ip)
        end_ip = ipaddress.ip_address(end_ip)
    except ValueError as e:
        print(f"Invalid IP address: {e}")
        exit(1)

    for ip in ipaddress.summarize_address_range(start_ip, end_ip):
        for host in ip:
            print(f"Scanning {host}...")
            if is_host_live(str(host)):
                print(f"{host} is live.")
                open_ports, closed_ports = scan_ports(str(host), ports)
                print(f"Open ports: {open_ports}")
                print(f"Closed ports: {closed_ports}")
            else:
                print(f"{host} is not live.")