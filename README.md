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

### Run as Executable

#### Linux System (bash / zsh)
```shell
export VERSION="v0.0.1-alpha"

# One-time download per version
wget -O site-discovery "https://github.com/GDC-ConsumerEdge/site-discovery/releases/download/${VERSION}$/siteDiscovery" && \
    chmod +x site-discovery

# Run the site discovery
./siteDiscovery --file <playbook.yaml>

# Optional
sudo mv ./siteDiscovery /usr/local/bin
```

#### Windows
```bat
@echo off
setlocal

:: Set the release version to download
set "VERSION=v0.0.1-alpha"

:: Define the output filename. Using .exe is standard for Windows executables.
set "FILENAME=site-discovery.exe"

:: Construct the download URL
set "URL=https://github.com/GDC-ConsumerEdge/site-discovery/releases/download/%VERSION%/siteDiscovery"

echo Downloading %FILENAME% from release %VERSION%...

:: Use curl to download the file.
:: -L follows redirects, which is important for GitHub.
:: -o specifies the output file name.
:: The "&&" operator ensures the next part only runs if the download succeeds.
curl -L -o "%FILENAME%" "%URL%"
```

### Run as Python

> NOTE: Optionally setup the venv environment defined in [developer documentation](docs/development.md)

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

```shell
./siteDiscovery --file playbook.yaml
System shell path is /usr/bin/bash
[INFO]log file /home/google/siteDiscovery/logs/site-discovery.log
[INFO]report file /home/google/siteDiscovery/logs/site-discovery-report_20241020-195123.txt
Loading Playbook /tmp/_XBCDJ7ql9w/playbook.yaml ...OK
Loading DNS mapping file /tmp/_XBCDJ7ql9w/dns_map.csv ...OK
Loading IP Address range (IPRR) file /tmp/_XBCDJ7ql9w/iprr.csv ...OK
Getting local network config ... NOK
Verify default gateway ... NOK
Verifying DNS Servers ... OK
Verifying NTP Servers ... OK
Verifying TCP connections ... 29/29
Verifying SSL connections ... 29/29
Verifying QBONE connections ... 40/40
Write report to /home/google/siteDiscovery/logs/site-discovery-report_20241020-195123.txt ... Done
```

## Disclaimer

This project is not an official Google project. It is not supported by
Google and Google specifically disclaims all warranties as to its quality, merchantability, or fitness for a particular purpose.