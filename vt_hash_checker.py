import requests
import time

banner = """
##############################################################
#                      VT Hash Checker                       #
##############################################################
# This script reads hashes from a file and checks each hash  #
# with VirusTotal's API. The results are categorized into    #
# 'malicious.txt' and 'non-malicious.txt' based on the       #
# analysis results.                                           #
#                                                            #
# - Malicious, Suspicious, and Undetected counts are         #
#   displayed for each hash.                                 #
# - A severity level (Low, Medium, High) is assigned based   #
#   on the malicious count.                                  #
# - The script pauses for 15 seconds between each request    #
#   to avoid hitting API rate limits.                        #
##############################################################
"""
print(banner)

API_KEY = "ENTER-YOUR-API-KEY-HERE"
API_URL = "https://www.virustotal.com/api/v3/files/{}"

headers = {
    "x-apikey": API_KEY
}

def get_file_report(file_id):
    url = API_URL.format(file_id)
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return {"error": "The requested resource does not exist"}
    else:
        return {"error": "An error occurred"}

def read_hashes_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def is_malicious(attributes):
    malicious_count = attributes.get('last_analysis_stats', {}).get('malicious', 0)
    return malicious_count > 0

def main():
 	
    file_path = r"/path/to/hashlist"
    malicious_file_path = r"/path/to/malicious.txt"
    non_malicious_file_path = r"/path/to/non-malicious.txt"
    
    hashes = read_hashes_from_file(file_path)
    
    with open(malicious_file_path, 'w') as malicious_file, open(non_malicious_file_path, 'w') as non_malicious_file:
        for file_hash in hashes:
            report = get_file_report(file_hash)
            
            if 'error' in report:
                print(f"Error getting report for {file_hash}: {report['error']}")
                continue

            attributes = report.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            malicious_count = last_analysis_stats.get('malicious', 0)
            undetected_count = last_analysis_stats.get('undetected', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)
            
            if malicious_count == 0:
                severity = "Low"
            elif 1 <= malicious_count <= 2:
                severity = "Medium"
            else:
                severity = "High"
            
            print(f"Report for {file_hash}:")
            print(f"Malicious Count: {malicious_count} - Severity: {severity}")
            print(f"Undetected Count: {undetected_count}")
            print(f"Suspicious Count: {suspicious_count}")
            print(f"Names: {', '.join(attributes.get('names', ['N/A']))}")
            
            if malicious_count > 0:
                malicious_file.write(f"{file_hash}\n")
            else:
                non_malicious_file.write(f"{file_hash}\n")
            
            # Sleep to avoid hitting API rate limits (15 sec recommended)
            time.sleep(15)

if __name__ == "__main__":
    main()
