# GDCC Site Discovery Tool

This tool is to do a pre-installation network validation for Google Distributed Cloud - Connected (GDCc)
It needs to be run in the intended network, to verify the network connectivity to Google services required by GDCc.

- DNS
- NTP
- Switch Management connections
- Google Cloud API endpoints
- VPN Connections

> :warning: NOTE: Best results when using the same physical ports on the switch(es)

## Running the tool

This tool can be run as an executable (ie: `.exe` or `+x`), as a Python script, or as a Docker container.

### Run as Python
#### activate virtual environment
- Linux System
```
source .venv/bin/activate
```
- Windows System
```
venv/Scripts/activate.bat
```
#### install required python package and run the script
```
python3 -m pip install -r requirements.txt
python3 main.py
```
### Command line options
```
# get help info
python3 main.py --help
# use custom playbook
python3 main.py --file your_playbook.yaml
```
Playbook exmaple is [here](playbook.yaml)


## Example outputs
The script will generate two text files
- [report file](site-discovery-report.example.txt) - connection validation for each endpoints in the playbook file
- [log file](site-discovery.example.log) - more detailed record of the test steps, e.g. the command sent to endpoints, and the response received back from the endpoints
```
(.venv) curr-user@curr-user-1:~/PycharmProjects/siteDiscovery/release/alpha$ ./siteDiscovery
System shell path is /usr/bin/bash
[INFO]log file /usr/local/google/home/curr-user/PycharmProjects/siteDiscovery/release/alpha/site-discovery.log
[INFO]report file /usr/local/google/home/curr-user/PycharmProjects/siteDiscovery/release/alpha/site-discovery-report_20241020-195123.txt
Loading Playbook /tmp/_MEIJ7ql9w/playbook.yaml ...OK
Loading DNS mapping file /tmp/_MEIJ7ql9w/dns_map.csv ...OK
Loading IP Address range (IPRR) file /tmp/_MEIJ7ql9w/iprr.csv ...OK
Getting local network config ... NOK
Verify default gateway ... NOK
Verifying DNS Servers ... OK
Verifying NTP Servers ... OK
Verifying TCP connections ... 29/29
Verifying SSL connections ... 29/29
Verifying QBONE connections ... 40/40
Write report to /usr/local/google/home/curr-user/PycharmProjects/siteDiscovery/release/alpha/site-discovery-report_20241020-195123.txt ... Done
```

## Disclaimer

This project is not an official Google project. It is not supported by
Google and Google specifically disclaims all warranties as to its quality,
merchantability, or fitness for a particular purpose.