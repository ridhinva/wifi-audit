#!/usr/bin/env python3
"""
WiFiAudit - WiFi Network Security Auditor
For authorized wireless security testing only.
"""

import argparse
import sys
import os
import re
import json
import csv
import subprocess
import time
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = RESET = ""
    class Style:
        RESET_ALL = ""

VERSION = "1.0.0"

WEAK_PASSWORDS = [
    "password", "12345678", "123456789", "1234567890", "qwerty123",
    "admin123", "letmein", "welcome", "abc12345", "password123",
]

CHANNELS_24GHZ = list(range(1, 14))
CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                  116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]


def run_cmd(cmd):
    """Run a system command and return output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def get_wireless_interfaces():
    """Get available wireless interfaces."""
    interfaces = []
    # Try iw
    stdout, _, rc = run_cmd("iw dev")
    if rc == 0:
        for line in stdout.split('\n'):
            if 'Interface' in line:
                iface = line.strip().split()[-1]
                interfaces.append(iface)

    # Try iwconfig
    if not interfaces:
        stdout, _, _ = run_cmd("iwconfig 2>/dev/null")
        for line in stdout.split('\n'):
            if 'IEEE 802.11' in line:
                iface = line.split()[0]
                interfaces.append(iface)

    return interfaces


def scan_networks_iw(interface):
    """Scan using iw (Linux)."""
    networks = []

    # Put interface in monitor mode temporarily
    run_cmd(f"ip link set {interface} down")
    run_cmd(f"iw dev {interface} set type monitor")
    run_cmd(f"ip link set {interface} up")

    # Scan
    stdout, stderr, rc = run_cmd(f"iw dev {interface} scan")
    if rc != 0:
        # Try managed mode scan
        run_cmd(f"iw dev {interface} set type managed")
        run_cmd(f"ip link set {interface} up")
        stdout, stderr, rc = run_cmd(f"iw dev {interface} scan")

    # Parse results
    current = {}
    for line in stdout.split('\n'):
        line = line.strip()
        if line.startswith('BSS '):
            if current:
                networks.append(current)
            bssid = line.split('(')[0].replace('BSS ', '').strip()
            current = {"bssid": bssid, "ssid": "", "channel": 0, "signal": 0,
                       "encryption": "Unknown", "wps": False}
        elif 'SSID:' in line:
            current["ssid"] = line.split('SSID:')[-1].strip()
        elif 'signal:' in line:
            match = re.search(r'signal:\s*(-?\d+\.?\d*)', line)
            if match:
                current["signal"] = float(match.group(1))
        elif 'DS Parameter set: channel' in line:
            match = re.search(r'channel\s*(\d+)', line)
            if match:
                current["channel"] = int(match.group(1))
        elif 'WPA:' in line or 'RSN:' in line:
            current["encryption"] = "WPA2/WPA3"
        elif 'WEP:' in line:
            current["encryption"] = "WEP"
        elif 'WPS' in line:
            current["wps"] = True

    if current:
        networks.append(current)

    # Restore managed mode
    run_cmd(f"iw dev {interface} set type managed")
    run_cmd(f"ip link set {interface} up")

    return networks


def scan_networks_nmcli():
    """Scan using nmcli (NetworkManager)."""
    networks = []
    stdout, _, rc = run_cmd("nmcli -t -f BSSID,SSID,CHAN,SIGNAL,SECURITY dev wifi list --rescan yes")

    if rc == 0:
        for line in stdout.split('\n'):
            if not line.strip():
                continue
            parts = line.split(':')
            if len(parts) >= 5:
                bssid = ':'.join(parts[:6]) if len(parts) >= 6 else parts[0]
                networks.append({
                    "bssid": bssid,
                    "ssid": parts[6] if len(parts) > 6 else parts[1] if len(parts) > 1 else "",
                    "channel": int(parts[-3]) if parts[-3].isdigit() else 0,
                    "signal": int(parts[-2]) if parts[-2].isdigit() else 0,
                    "encryption": parts[-1] if parts[-1] else "Open",
                    "wps": False,
                })

    return networks


def scan_networks_fallback():
    """Fallback scan using iwlist."""
    interfaces = get_wireless_interfaces()
    networks = []

    for iface in interfaces:
        stdout, _, rc = run_cmd(f"iwlist {iface} scan 2>/dev/null")
        if rc != 0:
            continue

        current = {}
        for line in stdout.split('\n'):
            line = line.strip()
            if 'Cell' in line and 'Address:' in line:
                if current:
                    networks.append(current)
                bssid = line.split('Address:')[-1].strip()
                current = {"bssid": bssid, "ssid": "", "channel": 0, "signal": 0,
                           "encryption": "Unknown", "wps": False}
            elif 'ESSID:' in line:
                current["ssid"] = line.split('ESSID:')[-1].strip('"')
            elif 'Channel:' in line:
                match = re.search(r'Channel:(\d+)', line)
                if match:
                    current["channel"] = int(match.group(1))
            elif 'Signal level' in line:
                match = re.search(r'Signal level[=:](-?\d+)', line)
                if match:
                    current["signal"] = int(match.group(1))
            elif 'Encryption key:on' in line:
                current["encryption"] = "WEP"
            elif 'WPA' in line:
                current["encryption"] = "WPA/WPA2"
            elif 'WPA2' in line:
                current["encryption"] = "WPA2"

        if current:
            networks.append(current)

    return networks


def scan_networks(interface=None):
    """Scan for WiFi networks using available tools."""
    print(f"\n{Fore.CYAN}[*] Scanning for WiFi networks...{Style.RESET_ALL}")

    networks = []

    # Try different methods
    if os.name == 'posix':
        if interface:
            networks = scan_networks_iw(interface)
        if not networks:
            networks = scan_networks_nmcli()
        if not networks:
            networks = scan_networks_fallback()

    if not networks:
        print(f"  {Fore.YELLOW}[!] No networks found or scanning not supported on this platform{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}[!] On Linux, run with sudo and ensure wireless tools are installed{Style.RESET_ALL}")

    return networks


def audit_network(network):
    """Audit a single network for security issues."""
    issues = []
    ssid = network.get("ssid", "")
    encryption = network.get("encryption", "").upper()
    wps = network.get("wps", False)

    # Check encryption
    if "OPEN" in encryption or encryption == "":
        issues.append({"severity": "HIGH", "issue": "Open network - no encryption"})
    elif "WEP" in encryption:
        issues.append({"severity": "CRITICAL", "issue": "WEP encryption - easily crackable"})

    # Check WPS
    if wps:
        issues.append({"severity": "HIGH", "issue": "WPS enabled - vulnerable to brute force"})

    # Check SSID
    if not ssid:
        issues.append({"severity": "LOW", "issue": "Hidden SSID detected"})
    elif ssid.lower() in ["linksys", "netgear", "dlink", "default", "home", "wifi",
                            "wireless", "admin", "test", "guest"]:
        issues.append({"severity": "MEDIUM", "issue": f"Default/generic SSID: {ssid}"})

    # Check signal (rogue AP detection hint)
    signal = network.get("signal", 0)
    if signal > -30:
        issues.append({"severity": "LOW", "issue": "Unusually strong signal - possible rogue AP nearby"})

    return issues


def detect_evil_twins(networks):
    """Detect potential evil twin access points."""
    print(f"\n{Fore.CYAN}[*] Checking for Evil Twin APs...{Style.RESET_ALL}")

    ssid_groups = {}
    for net in networks:
        ssid = net.get("ssid", "")
        if ssid:
            ssid_groups.setdefault(ssid, []).append(net)

    evil_twins = []
    for ssid, group in ssid_groups.items():
        if len(group) > 1:
            bssids = [n["bssid"] for n in group]
            encryptions = set(n.get("encryption", "") for n in group)

            if len(encryptions) > 1:
                evil_twins.append({
                    "ssid": ssid,
                    "count": len(group),
                    "bssids": bssids,
                    "encryptions": list(encryptions),
                    "issue": "Same SSID with different encryption - possible evil twin",
                })

    for et in evil_twins:
        print(f"  {Fore.RED}[!] Evil Twin suspected: {et['ssid']}{Style.RESET_ALL}")
        print(f"      BSSIDs: {', '.join(et['bssids'])}")
        print(f"      Encryptions: {', '.join(et['encryptions'])}")

    return evil_twins


def analyze_channels(networks):
    """Analyze channel congestion."""
    print(f"\n{Fore.CYAN}[*] Channel Analysis:{Style.RESET_ALL}\n")

    channel_count = {}
    for net in networks:
        ch = net.get("channel", 0)
        if ch > 0:
            channel_count[ch] = channel_count.get(ch, 0) + 1

    for ch in sorted(channel_count.keys()):
        count = channel_count[ch]
        bar = "█" * count
        color = Fore.RED if count > 3 else Fore.YELLOW if count > 1 else Fore.GREEN
        band = "5GHz" if ch > 14 else "2.4GHz"
        print(f"  {Fore.WHITE}CH {ch:>3}{Style.RESET_ALL} ({band}): {color}{bar} ({count}){Style.RESET_ALL}")

    congested = [ch for ch, count in channel_count.items() if count > 3]
    if congested:
        print(f"\n  {Fore.YELLOW}[!] Congested channels: {', '.join(map(str, congested))}{Style.RESET_ALL}")

    return channel_count


def print_networks(networks):
    """Print discovered networks."""
    print(f"\n{Fore.CYAN}{'='*80}")
    print(f"  {'SSID':<25} {'BSSID':<18} {'CH':>3} {'Signal':>7} {'Encryption':<12} {'WPS':>4}")
    print(f"{'='*80}{Style.RESET_ALL}")

    for net in sorted(networks, key=lambda x: x.get("signal", 0), reverse=True):
        ssid = net.get("ssid", "<hidden>")[:24]
        bssid = net.get("bssid", "N/A")[:17]
        channel = str(net.get("channel", "?"))[:3]
        signal = net.get("signal", 0)
        encryption = net.get("encryption", "Unknown")[:11]
        wps = "Yes" if net.get("wps") else "No"

        # Color based on signal
        if signal > -50:
            sig_color = Fore.GREEN
        elif signal > -70:
            sig_color = Fore.YELLOW
        else:
            sig_color = Fore.RED

        # Color based on encryption
        if "OPEN" in encryption.upper() or not encryption:
            enc_color = Fore.RED
        elif "WEP" in encryption.upper():
            enc_color = Fore.RED
        elif "WPA3" in encryption.upper():
            enc_color = Fore.GREEN
        else:
            enc_color = Fore.YELLOW

        print(f"  {ssid:<25} {bssid:<18} {channel:>3} {sig_color}{signal:>5} dBm{Style.RESET_ALL} "
              f"{enc_color}{encryption:<12}{Style.RESET_ALL} {wps:>4}")


def export_results(networks, filename, fmt="json"):
    """Export scan results."""
    if fmt == "json":
        report = {
            "tool": "WiFiAudit",
            "version": VERSION,
            "scan_time": datetime.now().isoformat(),
            "networks": networks,
        }
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
    elif fmt == "csv":
        with open(filename, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(["SSID", "BSSID", "Channel", "Signal", "Encryption", "WPS", "Issues"])
            for net in networks:
                issues = audit_network(net)
                w.writerow([net.get("ssid"), net.get("bssid"), net.get("channel"),
                           net.get("signal"), net.get("encryption"), net.get("wps"),
                           "; ".join(i["issue"] for i in issues)])

    print(f"\n{Fore.GREEN}[+] Results exported to {filename}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="WiFiAudit - WiFi Network Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo %(prog)s scan
  sudo %(prog)s scan -i wlan0
  sudo %(prog)s audit
  sudo %(prog)s rogue --known known_networks.txt
  %(prog)s channels
  sudo %(prog)s scan --report json --output wifi.json
        """
    )

    sub = parser.add_subparsers(dest="command")

    # scan
    s = sub.add_parser("scan", help="Scan for WiFi networks")
    s.add_argument("-i", "--interface", help="Wireless interface")
    s.add_argument("--report", choices=["json", "csv"], help="Export format")
    s.add_argument("--output", help="Output filename")

    # audit
    a = sub.add_parser("audit", help="Audit WiFi security")
    a.add_argument("-i", "--interface", help="Wireless interface")
    a.add_argument("--bssid", help="Specific BSSID to audit")

    # rogue
    r = sub.add_parser("rogue", help="Detect rogue access points")
    r.add_argument("--known", required=True, help="File with known network BSSIDs")
    r.add_argument("-i", "--interface", help="Wireless interface")

    # evil-twin
    e = sub.add_parser("evil-twin", help="Detect evil twin APs")
    e.add_argument("-i", "--interface", help="Wireless interface")

    # channels
    c = sub.add_parser("channels", help="Analyze channel congestion")
    c.add_argument("-i", "--interface", help="Wireless interface")

    args = parser.parse_args()

    print(f"\n{Fore.CYAN}╔══════════════════════════════════╗")
    print(f"║    WiFiAudit v{VERSION}             ║")
    print(f"╚══════════════════════════════════╝{Style.RESET_ALL}")

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        networks = scan_networks(getattr(args, 'interface', None))
        if networks:
            print_networks(networks)
            if args.report:
                export_results(networks, args.output or "wifi_scan.json", args.report)
        else:
            print(f"\n  {Fore.YELLOW}[!] No networks found. On Linux, run with: sudo python3 wifiaudit.py scan{Style.RESET_ALL}")

    elif args.command == "audit":
        networks = scan_networks(getattr(args, 'interface', None))
        if networks:
            print_networks(networks)
            print(f"\n{Fore.CYAN}{'='*50}")
            print(f"  SECURITY AUDIT")
            print(f"{'='*50}{Style.RESET_ALL}")

            for net in networks:
                if args.bssid and net.get("bssid") != args.bssid:
                    continue
                issues = audit_network(net)
                if issues:
                    ssid = net.get("ssid", "<hidden>")
                    print(f"\n  {Fore.WHITE}{ssid} ({net.get('bssid', 'N/A')}):{Style.RESET_ALL}")
                    for issue in issues:
                        color = {"CRITICAL": Fore.RED, "HIGH": Fore.RED,
                                 "MEDIUM": Fore.YELLOW, "LOW": Fore.CYAN}[issue["severity"]]
                        print(f"    {color}[{issue['severity']}] {issue['issue']}{Style.RESET_ALL}")
                else:
                    ssid = net.get("ssid", "<hidden>")
                    print(f"  {Fore.GREEN}[+] {ssid}: No issues detected{Style.RESET_ALL}")

    elif args.command == "evil-twin":
        networks = scan_networks(getattr(args, 'interface', None))
        if networks:
            detect_evil_twins(networks)

    elif args.command == "rogue":
        networks = scan_networks(getattr(args, 'interface', None))
        if networks:
            with open(args.known) as f:
                known = set(line.strip().upper() for line in f if line.strip())

            print(f"\n{Fore.CYAN}[*] Checking for rogue APs ({len(known)} known networks)...{Style.RESET_ALL}")
            for net in networks:
                if net.get("bssid", "").upper() not in known:
                    print(f"  {Fore.RED}[!] Unknown AP: {net.get('ssid', '<hidden>')} ({net.get('bssid')}){Style.RESET_ALL}")

    elif args.command == "channels":
        networks = scan_networks(getattr(args, 'interface', None))
        if networks:
            analyze_channels(networks)


if __name__ == "__main__":
    main()
