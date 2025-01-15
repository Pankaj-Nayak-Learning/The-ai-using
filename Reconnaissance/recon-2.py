import os
import subprocess

def run_command(command, description=""):
    """Run a command and return the output."""
    print(f"\n[+] {description}...")
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        if result.stdout:
            print(result.stdout.strip())
        if result.stderr:
            print(f"Error: {result.stderr.strip()}")
        return result.stdout.strip()
    except Exception as e:
        print(f"[-] Error running command: {e}")
        return ""

def dns_lookup(domain):
    """Perform DNS lookup."""
    return run_command(f"nslookup {domain}", "Performing DNS lookup")

def whois_lookup(domain):
    """Perform WHOIS lookup."""
    return run_command(f"whois {domain}", "Performing WHOIS lookup")

def reverse_dns_lookup(ip):
    """Perform reverse DNS lookup."""
    return run_command(f"nslookup {ip}", "Performing reverse DNS lookup")

def nmap_scan(ip):
    """Perform Nmap scan."""
    return run_command(f"nmap -sS -sV -O --top-ports 20 {ip}", "Performing Nmap scan (Top 20 Ports)")

def subdomain_enum(domain):
    """Perform subdomain enumeration."""
    return run_command(f"sublist3r -d {domain}", "Enumerating subdomains with Sublist3r")

def service_specific_enum(ip):
    """Perform targeted enumeration for services."""
    smb_enum = run_command(f"smbclient -L //{ip} -N", "Enumerating SMB shares")
    return smb_enum

def directory_discovery(ip):
    """Perform directory and file discovery."""
    return run_command(f"gobuster dir -u http://{ip} -w /usr/share/wordlists/dirb/common.txt", "Discovering directories with Gobuster")

def ssl_analysis(ip):
    """Perform SSL/TLS analysis."""
    return run_command(f"sslscan {ip}", "Analyzing SSL/TLS with sslscan")

def save_to_file(data, filename="comprehensive_recon_output.txt"):
    """Save all reconnaissance data to a file."""
    with open(filename, "w") as file:
        file.write(data)
    print(f"[+] Results saved to {filename}")

if __name__ == "__main__":
    target = input("Enter the target domain or IP: ")
    is_ip = target.replace(".", "").isdigit()
    
    results = ""

    if is_ip:
        # If target is an IP
        results += f"Target: {target} (IP Address)\n"
        results += "=" * 50 + "\n"
        results += reverse_dns_lookup(target) + "\n\n"
        results += nmap_scan(target) + "\n\n"
        results += service_specific_enum(target) + "\n\n"
        results += directory_discovery(target) + "\n\n"
        results += ssl_analysis(target) + "\n\n"
    else:
        # If target is a domain
        results += f"Target: {target} (Domain Name)\n"
        results += "=" * 50 + "\n"
        results += dns_lookup(target) + "\n\n"
        results += whois_lookup(target) + "\n\n"
        results += subdomain_enum(target) + "\n\n"
        resolved_ip = run_command(f"nslookup {target} | grep Address | tail -n 1 | awk '{{print $2}}'", "Resolving domain to IP")
        if resolved_ip:
            results += f"Resolved IP: {resolved_ip}\n"
            results += nmap_scan(resolved_ip) + "\n\n"
            results += service_specific_enum(resolved_ip) + "\n\n"
            results += directory_discovery(resolved_ip) + "\n\n"
            results += ssl_analysis(resolved_ip) + "\n\n"

    save_to_file(results)
    print("\n[+] Comprehensive reconnaissance and scanning complete.")
