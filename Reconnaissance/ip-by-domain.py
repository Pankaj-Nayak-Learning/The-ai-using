import socket

def find_ip_by_domain(domain):
    try:
        print(f"[+] Resolving IP address for domain: {domain}")
        ip_address = socket.gethostbyname(domain)
        print(f"[+] IP address for {domain}: {ip_address}")
        return ip_address
    except socket.gaierror as e:
        print(f"[-] Failed to resolve IP address for domain: {domain}. Error: {e}")
        return None

if __name__ == "__main__":
    domain = input("Enter the domain name: ")
    ip = find_ip_by_domain(domain)
    if ip:
        print(f"The IP address for {domain} is: {ip}")
    else:
        print(f"Could not find an IP address for {domain}.")
