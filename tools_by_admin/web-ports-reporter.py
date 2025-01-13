import nmap
import sys
import json

def scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-A')

    report = []
    for host in nm.all_hosts():
        host_info = {
            'host': host,
            'hostname': nm[host].hostname(),
            'state': nm[host].state(),
            'protocols': []
        }
        for proto in nm[host].all_protocols():
            protocol_info = {
                'protocol': proto,
                'ports': []
            }
            lport = nm[host][proto].keys()
            for port in lport:
                port_info = {
                    'port': port,
                    'state': nm[host][proto][port]['state'],
                    'name': nm[host][proto][port]['name'],
                    'product': nm[host][proto][port]['product'],
                    'version': nm[host][proto][port]['version'],
                    'extrainfo': nm[host][proto][port]['extrainfo']
                }
                protocol_info['ports'].append(port_info)
            host_info['protocols'].append(protocol_info)
        report.append(host_info)
    
    return report

def generate_report(report):
    print("Nmap Scan Report")
    print("================")
    for host in report:
        print(f"Host: {host['host']} ({host['hostname']})")
        print(f"State: {host['state']}")
        for proto in host['protocols']:
            print(f"Protocol: {proto['protocol']}")
            for port in proto['ports']:
                print(f"Port: {port['port']}")
                print(f"State: {port['state']}")
                print(f"Service: {port['name']}")
                print(f"Product: {port['product']}")
                print(f"Version: {port['version']}")
                print(f"Extra Info: {port['extrainfo']}")
                print("")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python web-ports-reporter.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    report = scan(target)
    generate_report(report)
    with open('scan_report.json', 'w') as f:
        json.dump(report, f, indent=4)
    print("Report saved to scan_report.json")