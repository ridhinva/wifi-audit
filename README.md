# WiFiAudit - WiFi Network Security Auditor

Audits WiFi network security by scanning for nearby networks, detecting weak configurations, identifying rogue access points, and checking for common WiFi vulnerabilities.

## Features

- Wireless network scanning
- WEP/WPA/WPA2/WPA3 security detection
- Hidden SSID detection
- Rogue access point detection
- Channel congestion analysis
- Signal strength mapping
- WPS vulnerability detection
- Evil twin detection
- CSV/JSON report generation

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/wifi-audit.git
cd wifi-audit
pip3 install -r requirements.txt
chmod +x wifiaudit.py

# Linux: Ensure wireless tools are available
sudo apt install wireless-tools iw
```

## Usage

### Scan WiFi Networks
```bash
# Basic scan
sudo python3 wifiaudit.py scan

# Scan with specific interface
sudo python3 wifiaudit.py scan -i wlan0

# Extended scan (longer duration for more results)
sudo python3 wifiaudit.py scan --duration 30
```

### Security Audit
```bash
# Audit all discovered networks
sudo python3 wifiaudit.py audit

# Audit specific network
sudo python3 wifiaudit.py audit --bssid AA:BB:CC:DD:EE:FF
```

### Detect Rogue APs
```bash
# Compare against known networks
sudo python3 wifiaudit.py rogue --known known_networks.txt

# Detect evil twins
sudo python3 wifiaudit.py evil-twin
```

### Channel Analysis
```bash
python3 wifiaudit.py channels
```

### Export Results
```bash
sudo python3 wifiaudit.py scan --report json --output wifi_scan.json
sudo python3 wifiaudit.py scan --report csv --output wifi_scan.csv
```

## Security Issues Detected

| Issue | Severity | Description |
|-------|----------|-------------|
| Open Network | HIGH | No encryption |
| WEP Encryption | CRITICAL | Easily crackable |
| WPS Enabled | HIGH | Brute-force vulnerable |
| Weak PSK | HIGH | Common/dictionary passwords |
| Hidden SSID | LOW | Security through obscurity |
| Channel Overlap | LOW | Performance issue |
| Rogue AP | CRITICAL | Unauthorized access point |

## Legal Disclaimer

WiFi scanning and auditing is only legal on networks you own or have explicit authorization to test. Unauthorized access to wireless networks is a federal crime in most countries.

## License

MIT License
