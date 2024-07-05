# GDCC Site Discovery Tool
This tool is to do a pre-installation network validation for Google Distributed Cloud - Connected (GDCC)
It needs to be run on customer's network, to verify the network connectivity to Google services required by GDCC.
- DNS
- NTP
- Switch Management connections
- Google Cloud API endpoints
- VPN Connections
## Getting started
This tool can be compiled to a single standalone executable file on Windows or Linux platform.
However, if for any security reason the executable file cannot run, user could also install a python virtual environment, and run it as a python script.
## Prepare the workspace
### clone the code repository
```
git clone https://github.com/daniell76/siteDiscovery.git
cd siteDiscovery
```
### create a virtual environment
Assuming python3 is already installed. Now create a python virtual environment under the project directory.
If using Pycharm, the IDE probably already did this step. Please skip this step if virtual environment is already created.
- Linux System: create a virtual environment in local `.venv` folder 
```
python3 -m venv .venv
```
- Windows System: create a virtual environment in local `venv` folder
```
python3 -m venv venv
```
## Build a standalone executables
- Linux System
```
build.sh
```
- Windows System
```
build.bat
```
binary executable is generated in `dist` folder

## Run as python script
### activate virtual environment
- Linux System
```
source .venv/bin/activate
```
- Windows System
```
venv/Scripts/activate.bat
```
### install required python package and run the script
```
python3 -m pip install -r requirements.txt
python3 main.py
```
## Command line options
```
# get help info
python3 main.py --help
# use custom playbook
python3 main.py --file your_playbook.yaml
```
Playbook exmaple is [here](playbook.yaml)
## Example outputs
The script will generate two text files
- [report file](site-discovery-report_20240705-203910.txt) - connection validation for each endpoints in the playbook file
- [log file](site-discovery.log) - more detailed record of the test steps, e.g. the command sent to endpoints, and the response received back from the endpoints
```
$ python3 main.py
System shell path is /usr/bin/bash
[INFO]log file /usr/local/google/home/danielxia/PycharmProjects/siteDiscovery/site-discovery.log
[INFO]report file /usr/local/google/home/danielxia/PycharmProjects/siteDiscovery/site-discovery-report_20240705-165135.txt
Loading Playbook /usr/local/google/home/danielxia/PycharmProjects/siteDiscovery/playbook.yaml ...OK
Getting local network config ... NOK
Verify default gateway ... NOK
Verifying DNS Servers ... OK
Verifying NTP Servers ... OK
Verifying TCP connections ... 23/23
Verifying SSL connections ... 32/32
Verifying QBONE connections ... 40/40
Write report to /usr/local/google/home/danielxia/PycharmProjects/siteDiscovery/site-discovery-report_20240705-165135.txt ... Done
```