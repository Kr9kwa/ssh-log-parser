# Name:Logs Parser

## Description:
This parser goes through the whole file and getting all lines that contain suspicious IP's. The main idea is to detect potential bruteforce.

## Features:
Three main functions are available for usage. 
- Function `parse_log_file()` returning three different dicts: `ip_attempts` that shows amount of attempts from the same IP address, `ip_timestamps` that shows ip and all dates and times when was attempt of log in, `ip_details` that shows ip, attempts, usernames and ports. 
- Function `detect_bruteforce()` returns all suspicious IPs address. 
- Function `full_analyze()` prints all details about suspicious IPs(ip, attempts, usernames, ports).

## Requirements: 
- Version Python 3.14.3. 
- Modules and libraries(all built in): `re`, `collections(Counter)`, `datetime`, `argparse`

## Usage:
`python "Logs Parser.py" logs.txt`


## Example output: 
```
[!] Suspicious IP: 203.0.113.45, Attempts: 4, User(s): {'test', 'admin', 'root'}, Ports: {'22'} 

[!] Suspicious IP: 10.0.0.5, Attempts: 3, User(s): {'test'}, Ports: {'22'}
```

## Known limitations: 
- datetime object requires year to create timedelta objects so in the program it was fixed by `datetime.now().year`. 
- Log files spanning New Year's Eve (Dec 31 → Jan 1) may produce incorrect `timedelta` results due to year mismatch.