import requests
import time

banner = """
###########################################################################
#                    VirusTotal Domain Checker Script                    #
###########################################################################
#                                                                         #
# This script automatically checks domains against VirusTotal's API and   #
# categorizes them into 'malicious.txt' and 'non-malicious.txt' based on  #
# the analysis results.                                                   #
#                                                                         #
# Features:                                                               #
# - Provides counts of Malicious, Suspicious, and Undetected statuses     #
#   for each domain.                                                      #
# - Also provides the detection methods used by the vendors.              #
# - Pauses for 5 seconds between each request to avoid API rate limits.   #
#                                                                         #
# Usage:                                                                  #
# 1. Set your VirusTotal API Key:                                         #
#    API_KEY = "YOUR_VIRUSTOTAL_API_KEY"                                  #
#                                                                         #
# 2. Specify the path to your domain list and output files:               #
#    file_path = r"/path/to/domainlist"                                   #
#    malicious_file_path = r"/path/to/malicious.txt"                      #
#    non_malicious_file_path = r"/path/to/non-malicious.txt"              #
#                                                                         #
# 3. Run the script:                                                      #
#    $ python vt_domain_checker.py                                        #
#                                                                         #
# The script will read domains from the specified list, check them        #
# against VirusTotal, and write the results to the specified output files.#
#                                                                         #
###########################################################################
"""
print(banner)


API_KEY = "INSERT-YOUR-API-KEY-HERE"
API_URL = "https://www.virustotal.com/api/v3/domains/{}"

headers = {
    "x-apikey": API_KEY
}

def get_domain_report(domain):
    url = API_URL.format(domain)
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return {"error": "The requested resource does not exist"}
    else:
        return {"error": "An error occurred"}

def read_domains_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def main():
    file_path = r"/path/to/domainlist"
    malicious_file_path = r"/path/to/malicious.txt"
    non_malicious_file_path = r"/path/to/non-malicious.txt"
    
    domains = read_domains_from_file(file_path)
    
    with open(malicious_file_path, 'w') as malicious_file, open(non_malicious_file_path, 'w') as non_malicious_file:
        for domain in domains:
            report = get_domain_report(domain)
            
            if 'error' in report:
                print(f"Error getting report for {domain}: {report['error']}")
                continue
            
            attributes = report.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            malicious_count = last_analysis_stats.get('malicious', 0)
            undetected_count = last_analysis_stats.get('undetected', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)
            method = ", ".join(attributes.get('method', ['N/A']))  # assuming 'method' is a list
            
            print(f"Report for {domain}:")
            print(f"Malicious Count: {malicious_count}")
            print(f"Undetected Count: {undetected_count}")
            print(f"Suspicious Count: {suspicious_count}")
            print(f"Method: {method}")
            
            if malicious_count > 0:
                malicious_file.write(f"{domain}\n")
            else:
                non_malicious_file.write(f"{domain}\n")
            
            time.sleep(5)

if __name__ == "__main__":
    main()
