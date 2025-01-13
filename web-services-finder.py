#!/usr/bin/python3
import nmap

print("Welcome to the Web Services Finder")
print("Enter the IP address you want to scan for web services")
ip = input("Enter the IP address: ")

nm = nmap.PortScanner()
nm.scan(ip, '80-1000')

for host in nm.all_hosts():
    print('----------------------------------------------------')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())
    for proto in nm[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)

        lport = nm[host][proto].keys()
        for port in lport:
            print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
            print('Service : %s' % nm[host][proto][port]['name'])
            print('Product : %s' % nm[host][proto][port]['product'])
            print('Version : %s' % nm[host][proto][port]['version'])
            print('CPE : %s' % nm[host][proto][port]['cpe'])
            print('----------------------------------------------------')

print("Scan completed")

