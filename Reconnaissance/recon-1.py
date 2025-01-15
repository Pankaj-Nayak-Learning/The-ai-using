import subprocess

def run_command(command):
    """Run a command in the shell and return the output."""
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error executing command: {str(e)}"

def reconnaissance_for_phase2(target):
    output_file = f"phase2_recon_{target.replace('.', '_')}.txt"
    print(f"[+] Gathering reconnaissance data for Phase-2 on: {target}")
    print(f"[+] Output will be saved to {output_file}\n")

    with open(output_file, "w") as file:
        # Write header
        file.write(f"Phase-2 Reconnaissance Data for: {target}\n")
        file.write("=" * 50 + "\n\n")

        # 1. DNS Information
        print("[+] Extracting DNS information...")
        dns_command = f"nslookup {target}"
        dns_info = run_command(dns_command)
        file.write("[+] DNS Information\n")
        file.write(dns_info + "\n\n")
        print("[+] DNS information gathered.")

        # 2. WHOIS Data (Registrar and Domain Info)
        print("[+] Extracting WHOIS data...")
        whois_command = f"whois {target} | grep -E 'Domain Name|Registrar|Creation Date|Expiry Date|Updated Date'"
        whois_info = run_command(whois_command)
        file.write("[+] WHOIS Data\n")
        file.write(whois_info + "\n\n")
        print("[+] WHOIS data extracted.")

        # 3. Port Scanning with Nmap
        print("[+] Scanning open ports and services...")
        nmap_command = f"nmap -sS -sV -O --top-ports 20 {target}"
        nmap_info = run_command(nmap_command)
        file.write("[+] Nmap Scan (Top Ports, Services, and OS)\n")
        file.write(nmap_info + "\n\n")
        print("[+] Port scan and service enumeration completed.")

    print(f"[+] Reconnaissance for Phase-2 complete! Results saved in {output_file}")

if __name__ == "__main__":
    target = input("Enter the target IP or domain: ")
    reconnaissance_for_phase2(target)
