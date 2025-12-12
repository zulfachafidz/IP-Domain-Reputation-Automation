# IP & Domain Reputation Automation

Automation tool for checking IP address and domain reputation using several integrated threat intelligence services.

---

## Integrated Services

### **1. VirusTotal**
- IP/domain reputation analysis
- Malicious/suspicious/harmless statistics
- Automatic WHOIS parsing

### **2. AbuseIPDB**
- Abuse Confidence Score
- Number of reports, countries, and ISPs

### **3. AlienVault OTX**
- Pulse detection for threat indicators
- Determines whether the target has a dangerous reputation

### **4. urlscan.io**
- URL scanning for domains/websites
- Domain, IP, ASN, country, and server information
- Scan results links and screenshots (without downloading files)

---

## Key Features

- Supports IP or domain input (automatic script recognizes format).
- Multi-platform reputation checking in a single execution.
- Output results in a neat and easy-to-read JSON format.
- Screenshots from urlscan.io are **not saved**, only displayed as URLs.
- Error handling in each API so that the process continues even if one of the services fails to respond.

---

## File Structure

```
main.py        # Main script
requirements.txt
README.md
```

---

## Requirements

- Python 3.x
- Libraries:
  - requests
  - json (built-in)
  - time (built-in)
  - os (built-in)

---

## Installation

Clone the repository:

```bash
git clone https://github.com/zulfachafidz/IP-Domain-Reputation-Automation.git
cd IP-Domain-Reputation-Automation
```

Install dependencies:

```bash
pip install -r requirements.txt
```
---

## How to Run

Run the command:

```bash
python main.py
```

Enter IP or domain:

```
Enter IP / URL: attacker.com
```

The output will be displayed in JSON format, including:

- Reputation of each service
- Scan result link from urlscan.io
- Screenshot link from urlscan.io (without automatic download)

---

## ⚠ Notes

- Use your own API key from each platform.
- Some APIs have rate limits, so responses may be delayed or fail.

---

## License

May be used for personal, research, educational, or SOC operational purposes.
Free to modify as needed.
