#!/usr/bin/env python3
"""
network_mapper.py

Automates LAN discovery and port/version scanning using ARP, Masscan, and Nmap.
"""
import subprocess
import argparse
import re
import os


def run_cmd(cmd, capture_output=False):
    """Run a shell command."""
    result = subprocess.run(cmd, shell=True, capture_output=capture_output, text=True)
    if result.returncode != 0:
        print(f"Command failed: {cmd}")
        if capture_output:
            print(result.stderr)
        exit(1)
    return result.stdout if capture_output else None


def dhcp_renew(interface):
    print(f"[+] Renewing DHCP lease on {interface}")
    run_cmd(f"sudo dhclient {interface}")


def get_network(interface):
    output = run_cmd(
        f"ip -4 -o addr show dev {interface} | awk '{{print $4}}'", capture_output=True
    ).strip()
    print(f"[+] Detected network: {output}")
    return output


def arp_ping_sweep(network, out_grep='alive.txt'):
    print(f"[+] Performing ARP ping sweep on {network}")
    run_cmd(f"sudo nmap -sn -PR {network} -oG {out_grep}")
    hosts = []
    with open(out_grep) as f:
        for line in f:
            if 'Up' in line:
                parts = line.split()
                hosts.append(parts[1])
    with open('hosts.lst', 'w') as f:
        f.write('\n'.join(hosts))
    print(f"[+] Found {len(hosts)} hosts: hosts.lst")
    return hosts


def masscan_scan(rate, ports, hosts_file, out_mass='masscan.out'):
    print(f"[+] Scanning ports {ports} on hosts in {hosts_file} with rate {rate}")
    run_cmd(f"sudo masscan -iL {hosts_file} -p{ports} --rate {rate} -oL {out_mass}")
    open_entries = []
    with open(out_mass) as f:
        for line in f:
            if line.startswith('open'):
                # format: open tcp 22 10.0.0.1
                parts = line.split()
                proto, port, ip = parts[1], parts[2], parts[3]
                open_entries.append(f"{ip}:{port}")
    with open('open-ports.lst', 'w') as f:
        f.write('\n'.join(open_entries))
    print(f"[+] Masscan found {len(open_entries)} open ports: open-ports.lst")
    return open_entries


def nmap_version_scan(hosts_file, ports, output_prefix='full-scan'):
    port_list = ','.join(sorted(set(ports)))
    print(f"[+] Running Nmap version/OS scan on ports: {port_list}")
    cmd = (
        f"sudo nmap -sS -sV -O --version-all -p {port_list} \
        -iL {hosts_file} -T4 -oA {output_prefix}"
    )
    run_cmd(cmd)
    print(f"[+] Nmap scan complete: {output_prefix}.nmap, .gnmap, .xml")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Automate LAN mapping.')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface to use')
    parser.add_argument('-r', '--rate', default='10000', help='Masscan rate (pps)')
    parser.add_argument('-p', '--ports', default='1-65535', help='Port range for Masscan')
    args = parser.parse_args()

    # 1. DHCP renew (optional)
    dhcp_renew(args.interface)

    # 2. Determine network CIDR
    network = get_network(args.interface)

    # 3. ARP ping sweep
    hosts = arp_ping_sweep(network)

    # 4. Masscan on discovered hosts
    masscan_results = masscan_scan(args.rate, args.ports, 'hosts.lst')
    # Extract ports only
    ports = [entry.split(':')[1] for entry in masscan_results]

    # 5. Nmap version and OS scan
    if ports:
        nmap_version_scan('hosts.lst', ports)
    else:
        print("[!] No open ports found to scan with Nmap.")

    print("[+] Discovery complete.")
