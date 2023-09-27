import requests
import time
import re


API_KEY = "INSERT-YOUR-API-KEY-HERE"
DOMAIN_API_URL = "https://www.virustotal.com/api/v3/domains/{}"
IP_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
FILE_API_URL = "https://www.virustotal.com/api/v3/files/{}"

headers = {
    "x-apikey": API_KEY
}

def print_banner():
    banner = f"""
    ╔════════════════════════════════════════════════════════════╗
    ║                                                            ║
    ║            🔒 VT Ultimate IoC Checker v1.0 🔒              ║
    ║                                                            ║
    ║     Developer: Marton Andrei                               ║
    ║     Description: This script automates the process of      ║
    ║     analyzing large lists of IoCs utilizing VirusTotal’s   ║
    ║     API v3. It segregates malicious IoCs efficiently from  ║
    ║     the list, providing detailed analysis statuses and     ║
    ║     severity levels.                                       ║
    ║                                                            ║
    ║     🛠 How to Use:                                         ║
    ║     1. Set API_KEY = "Your VirusTotal API Key"             ║
    ║     2. Fill the "ioclist.txt" with the IoCs to be checked  ║
    ║     3. Run the script and review the results on screen     ║
    ║        and in the "malicious.txt" and "non-malicious.txt"  ║
    ║        files.                                              ║
    ║                                                            ║
    ╚════════════════════════════════════════════════════════════╝
    """
    print(banner)

def get_report(api_url, indicator):
    url = api_url.format(indicator)
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error {response.status_code}: Unable to get report for {indicator}. Might not be in VirusTotal database.")
        return None

def read_iocs_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def get_severity_level(count):
    if count > 1:
        return 'High'
    elif count == 1:
        return 'Medium'
    else:
        return 'Low'

def is_ip(ioc):
    # Regular expression to match valid IPv4 addresses
    pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    return pattern.match(ioc)

def main():
    file_path = r"ioclist.txt"
    malicious_file_path = r"malicious.txt"
    non_malicious_file_path = r"non-malicious.txt"
    unchecked_file_path = r"unchecked.txt"

    iocs = read_iocs_from_file(file_path)

    with open(malicious_file_path, 'w') as malicious_file, open(non_malicious_file_path, 'w') as non_malicious_file, open(unchecked_file_path, 'w') as unchecked_file:
        for ioc in iocs:
            api_url = ""
            if is_ip(ioc):  # IP address
                api_url = IP_API_URL
            elif '.' in ioc:  # Domain or Hash
                if len(ioc.split('.')) > 1 and ioc.split('.')[-1].isalpha():  # Domain
                    api_url = DOMAIN_API_URL
                else:  # Hash
                    api_url = FILE_API_URL
            else:  # Hash
                api_url = FILE_API_URL

            report = get_report(api_url, ioc)
            if not report:
                unchecked_file.write(f"{ioc}\n")
                continue

            attributes = report.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            malicious_count = last_analysis_stats.get('malicious', 0)
            undetected_count = last_analysis_stats.get('undetected', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)

            print(f"Report for {ioc}:")
            print(f"Malicious Count: {malicious_count}")
            print(f"Undetected Count: {undetected_count}")
            print(f"Suspicious Count: {suspicious_count}")
            print(f"Severity Level: {get_severity_level(malicious_count + suspicious_count)}\n")

            if malicious_count > 0 or suspicious_count > 0:
                malicious_file.write(f"{ioc}\n")
            else:
                non_malicious_file.write(f"{ioc}\n")

            time.sleep(15)  # to respect the API request rate limit

if __name__ == "__main__":
	print_banner()
	main()
