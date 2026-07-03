import re
from collections import Counter
import datetime
import argparse

#Creating octet pattern
octet = r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])'
#Creating ip pattern from 4 octets
ip_pattern = rf"\b({octet}\.{octet}\.{octet}\.{octet})\b"
#Creating status pattern to identify if log was successful or no
status_pattern = r'Failed|Accepted'
#Creating date of log pattern to identify when was attempt to log in
date_pattern = r'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (3[0-1]|2[0-9]|1[0-9]|[0-9]) (2[0-4]|1[0-9]|[0-9]):[0-5][0-9]:[0-5][0-9]'
#Creting username pattern for identifying what user was trying to log in
username_pattern = r'for (invalid user )?(.+?) from'
#Creating port pattern to get the port from was attempt to log in
port_pattern = r'port (\d+)'


def parse_log_file(filepath):
    ''' Parses SSH auth log file and returns failed login attempts data(Counter object ip_attempts(attempts of log in from the same IP),
    ip_timestamps(date and time when attempt to log in was made), ip_details(ip, attempts, username, port). '''
    ip_attempts = Counter()
    ip_timestamps = {}
    ip_details = {}
    with open(filepath, 'r') as file:
        for line in file:
            status = re.search(status_pattern, line)
            ip = re.search(ip_pattern, line)
            date_match = re.search(date_pattern, line)
            username_match = re.search(username_pattern, line)
            port_match = re.search(port_pattern, line)
            #Getting all IPs where log in was Failed
            if status and status.group() == 'Failed' and ip and date_match and username_match and port_match:
                ip_attempts[ip.group(1)] += 1
                # Add current year to avoid strptime default year warning (Python 3.15+)
                datetime_str = str(datetime.datetime.now().year) + ' ' + date_match.group()
                dt = datetime.datetime.strptime(datetime_str, '%Y %b %d %H:%M:%S')
                if ip.group(1) in ip_details:
                    ip_details[ip.group(1)].append((username_match.group(2), port_match.group(1)))
                else:
                    ip_details[ip.group(1)] = [(username_match.group(2),port_match.group(1))]
                if ip.group(1) in ip_timestamps:
                    ip_timestamps[ip.group(1)].append(dt)
                else:
                    ip_timestamps[ip.group(1)] = [dt]
    return ip_attempts, ip_timestamps, ip_details

def detect_bruteforce(ip_time_dict):
    '''This function detects suspicious IP addresses using potential bruteforce algorithm.'''
    suspicious_ips = []
    for ip, time in ip_time_dict.items():
        if len(time) >= 3:
            #iteration through the ip's timestamps
            for i in range(len(time)-1):
                cnt = 0
                #sliding window: count attempts within 5-minute range
                for j in range(i+1, len(time)):
                    #condition below check if current attempt was made between first attempt and five minutes
                    if time[i] <= time[j] <= time[i] + datetime.timedelta(minutes=5):
                        cnt += 1
                #checking if amount of failed attempts was more than 2 for five minutes
                if cnt >= 2:
                    suspicious_ips.append(ip)
                    # break to avoid adding the same IP multiple times
                    break

    return suspicious_ips

def full_analyze(suspicious_ips, ip_details, ip_attempts):
    '''This function prints dict with full information about suspicious IPs'''
    for i in suspicious_ips:
        #list comprehension is needed to unpack and sort tuples(username, port) and leave only unique objects
        print(f"[!] Suspicious IP: {i}, Attempts: {ip_attempts[i]}, User(s): {set([entry[0]for entry in ip_details[i]])}, Ports: {set([entry[1]for entry in ip_details[i]])}")


# Entry point: parse log, detect bruteforce, display results
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SSH log parser')
    parser.add_argument('filepath', help='Path to log file')
    args = parser.parse_args()
    ip_attempts, ip_timestamps, ip_details = parse_log_file(args.filepath)
    suspicious = detect_bruteforce(ip_timestamps)
    full_analyze(suspicious, ip_details, ip_attempts)