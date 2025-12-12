import requests
import json
import time
import os

# api

VIRUSTOTAL_API_KEY = "18fd47f38806f9d7abcc6dec2922f881ec6f9589d03af5c3fa895d7b8beb8f55"
ABUSEIPDB_API_KEY = "b7b7ff5c24aa96c2c667f38ce64d0cf8a6ac38c20814ea0cbccca1997633fa2f5801e70aabf3e77a"
ALIENVAULT_API_KEY = "03f83bd98fac1b225def6b32fa571aeb81362e5e2e35f38fbe89ef141d79ffeb"
URLSCAN_API_KEY = "0199e0a9-230a-7732-a9b9-58644b48dc0d"


def check_virustotal(target):
    # detect target is ip or domain
    if target.replace('.', '').isdigit():
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{target}"

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attr = data["data"]["attributes"]
        stats = attr.get("last_analysis_stats", {})

        whois_info = attr.get("whois", "Tidak ada data WHOIS")

        if isinstance(whois_info, str):
            whois_lines = whois_info.splitlines()
            whois_parsed = {}
            for line in whois_lines:
                if ":" in line:
                    key, value = line.split(":", 1)
                    whois_parsed[key.strip()] = value.strip()
        else:
            whois_parsed = whois_info

        return {
            "source": "VirusTotal",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "whois": whois_parsed,
        }
    else:
        return {"source": "VirusTotal", "error": response.text}

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        d = response.json()["data"]
        return {
            "source": "AbuseIPDB",
            "abuseConfidenceScore": d.get("abuseConfidenceScore"),
            "countryCode": d.get("countryCode"),
            "totalReports": d.get("totalReports"),
            "isp": d.get("isp"),
        }
    else:
        return {"source": "AbuseIPDB", "error": response.text}

def check_alienvault(target):
    if target.replace('.', '').isdigit():
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/general"
    else:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/general"

    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        pulse_count = len(data.get("pulse_info", {}).get("pulses", []))
        return {
            "source": "AlienVault OTX",
            "pulse_count": pulse_count,
            "reputation": "Malicious" if pulse_count > 0 else "Clean"
        }
    else:
        return {"source": "AlienVault OTX", "error": response.text}

def check_urlscan(url_to_check):
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }

    data = {"url": url_to_check, "visibility": "public"}

    response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
    if response.status_code != 200:
        return {"source": "urlscan.io", "error": response.text}

    scan_data = response.json()
    uuid = scan_data.get("uuid")

    print("[*] Waiting for IP or Domain analysis results (approximately 15-20 seconds)...")
    time.sleep(20)

    result_url = f"https://urlscan.io/api/v1/result/{uuid}/"
    result_resp = requests.get(result_url)

    if result_resp.status_code == 200:
        result = result_resp.json()
        screenshot_url = result.get("screenshot")
        page = result.get("page", {})

        info = {
            "source": "urlscan.io",
            "scan_result_url": f"https://urlscan.io/result/{uuid}/",
            "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
            "domain": page.get("domain"),
            "ip": page.get("ip"),
            "asn": page.get("asnname"),
            "country": page.get("country"),
            "server": page.get("server"),
        }

        if screenshot_url:
            ss = requests.get(screenshot_url)
            if ss.status_code == 200:
                os.makedirs("screenshots", exist_ok=True)
                filename = f"screenshots/{uuid}.png"
                with open(filename, "wb") as f:
                    f.write(ss.content)
                info["saved_screenshot"] = filename

        return info
    else:
        return {"source": "urlscan.io", "error": result_resp.text}

def check_reputation(target):
    print(f"\n🔍 Checking reputation for: {target}\n")
    results = []

    try:
        results.append(check_virustotal(target))
    except Exception as e:
        results.append({"source": "VirusTotal", "error": str(e)})

    try:
        if target.replace('.', '').isdigit():
            results.append(check_abuseipdb(target))
    except Exception as e:
        results.append({"source": "AbuseIPDB", "error": str(e)})

    try:
        results.append(check_alienvault(target))
    except Exception as e:
        results.append({"source": "AlienVault OTX", "error": str(e)})

    try:
        if not target.replace('.', '').isdigit():
            results.append(check_urlscan(target))
    except Exception as e:
        results.append({"source": "urlscan.io", "error": str(e)})

    print(json.dumps(results, indent=4, ensure_ascii=False))
    return results


if __name__ == "__main__":
    target = input("Enter IP / URL for check : ").strip()
    check_reputation(target)

