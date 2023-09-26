import requests
import time

banner = r"""
#################################################
#          VIRUSTOTAL IP CHECKER v1.0           #
#-----------------------------------------------#
#        Developed by Marton Andrei	            #
#                                               #
#-----------------------------------------------#
#  USAGE:                                       #
#  1. Set your VirusTotal API key by replacing  #
#     the value of API_KEY in the script.       #
#  2. Set the paths of the input IP list,       #
#     malicious.txt, and non-malicious.txt      #
#     by modifying the values of file_path,     #
#     malicious_file_path, and                  #
#     non_malicious_file_path respectively.     #
#  3. Run the script.                           #
#-----------------------------------------------#
#  DISCLAIMER:                                  #
#  This tool is intended for security research  #
#  and testing, use responsibly.                #
#################################################
"""

print(banner)


API_KEY = "INSERT-YOUR-API-KEY-HERE"
API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"

headers = {
    "x-apikey": API_KEY
}

def get_ip_report(ip_address):
    url = API_URL.format(ip_address)
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return {"error": "The requested resource does not exist"}
    else:
        return {"error": "An error occurred"}

def read_ips_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def main():
    file_path = r"/path/to/iplist"
    malicious_file_path = r"/path/to/malicious.txt"
    non_malicious_file_path = r"/path/to/non-malicious.txt"
    
    ips = read_ips_from_file(file_path)
    
    with open(malicious_file_path, 'w') as malicious_file, open(non_malicious_file_path, 'w') as non_malicious_file:
        for ip in ips:
            report = get_ip_report(ip)
            
            if 'error' in report:
                print(f"Error getting report for {ip}: {report['error']}")
                continue
            
            attributes = report.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            as_owner = attributes.get('as_owner', 'N/A')
            malicious_count = last_analysis_stats.get('malicious', 0)
            undetected_count = last_analysis_stats.get('undetected', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)
            
            engine_names = ", ".join([engine for engine, result in attributes.get('last_analysis_results', {}).items() if result['category'] == 'malicious'])
            
            print(f"Report for {ip}:")
            print(f"AS Owner: {as_owner}")
            print(f"Malicious Count: {malicious_count}")
            print(f"Undetected Count: {undetected_count}")
            print(f"Suspicious Count: {suspicious_count}")
            print(f"Engine Names: {engine_names}")
            
            if malicious_count > 0:
                malicious_file.write(f"{ip}\n")
            else:
                non_malicious_file.write(f"{ip}\n")
            
            time.sleep(5)  # adjust this to meet your specific rate limit needs

if __name__ == "__main__":
    main()
