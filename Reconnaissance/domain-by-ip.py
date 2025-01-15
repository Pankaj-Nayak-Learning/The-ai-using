import socket

def find_domain(ip_address):
    try:
        print(f"[+] Performing reverse DNS lookup for IP: {ip_address}")
        domain_name = socket.gethostbyaddr(ip_address)[0]
        print(f"[+] Domain name found: {domain_name}")
        return domain_name
    except socket.herror as e:
        print(f"[-] Unable to find a domain name for IP: {ip_address}. Error: {e}")
        return None

if __name__ == "__main__":
    ip = input("Enter the IP address: ")
    domain = find_domain(ip)
    if domain:
        print(f"Domain name for IP {ip}: {domain}")
    else:
        print(f"No domain name found for IP {ip}")
