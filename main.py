# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import argparse
from siteDiscoveryTool import SiteDiscoveryTool
from utils import *


def main():

    proj_dir = os.path.dirname(__file__)

    # Process input arguments
    parser = argparse.ArgumentParser(description="GDCE Site Discovery tool")
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        default=os.path.join(proj_dir, 'playbook.yaml'),
        help="playbook yaml file. Default is 'playbook.yaml' in the installation directory"
    )
    parser.add_argument(
        "-l",
        "--log_dir",
        type=str,
        default=os.getcwd(),
        help="log directory. Default is current working directory. log file name is 'site-discovery.log'"
    )
    parser.add_argument(
        "-r",
        "--report_dir",
        type=str,
        default=os.getcwd(),
        help="""report directory. Default is the current working directory.
        report file name is 'site-discovery-report_<timestamp>.txt'. timestamp = YYYYmmDD-HHMMSS"""
    )
    parser.add_argument(
        "-m",
        "--dns_mapper",
        type=str,
        default=os.path.join(proj_dir, 'dns_map.csv'),
        help="""DNS name mapper file. Binding regular GCP API endpoints to GDC-C specific ones. 
        Default is 'dns_map.csv' in the installation directory"""
    )
    parser.add_argument(
        "-a",
        "--iprr",
        type=str,
        default=os.path.join(proj_dir, 'iprr.csv'),
        help="""API IP address range file. Resolved endpoint IPv4 address should be in this range. 
        Default is 'iprr.csv' in the installation directory"""
    )
    args = parser.parse_args()
    config_dict = {
        'playbook': args.file,
        'log_dir': args.log_dir,
        'report_dir': args.report_dir,
        'dns_mapper': args.dns_mapper,
        'iprr': args.iprr
    }

    # Create tool instances
    tool = SiteDiscoveryTool()
    log = Logger()

    # add log file
    # t_now = datetime.now()
    # log_file_name = f"site-discovery_{t_now.strftime('%Y%m%d-%H%M%S')}.log"
    # log_file_path = os.path.join(config_dict['out_dir'], log_file_name)
    log_file_name = os.path.join(config_dict['log_dir'], 'site-discovery.log')
    try:
        log_file = open(log_file_name, 'a')
        log.add_output(log_file)
        print(f'[INFO]log file {log_file_name}')
    except:
        print(f'[WARN]Failed to open log file {log_file_name}')
        log.add_output(sys.stdout)  # log to stdout instead
    tool.bind_logger(log)

    # Report file
    t_str = datetime.now().strftime('%Y%m%d-%H%M%S')
    report_file_name = os.path.join(config_dict['report_dir'], f'site-discovery-report_{t_str}.txt')
    try:
        report_file = open(report_file_name, 'w+')
        print(f'[INFO]report file {report_file_name}')
        tool.bind_reporter(report_file)
    except:
        print(f'[WARN]Failed to create report file {report_file_name}')

    # Start Execution
    log.print('='*60, timestamp=False)

    # load playbook
    print(f"Loading Playbook {config_dict['playbook']} ...", end='')
    with open(config_dict['playbook'], 'r') as input_file:
        if not tool.load_playbook(input_file):
            print('NOK.')
            print(f"Invalid playbook YAML file {config_dict['playbook']}!")
            return
    print('OK')
    # print(tool.playbook)

    # load dns mapping file
    print(f"Loading DNS mapping file {config_dict['dns_mapper']} ...", end='')
    if not tool.load_dns_mapper(config_dict['dns_mapper']):
        print('NOK.')
        print(f"Invalid DNS mapping file {config_dict['dns_mapper']}!")
        return
    print('OK')

    # load network ranges file
    print(f"Loading IP Address range (IPRR) file {config_dict['iprr']} ...", end='')
    if not tool.load_ip_address_ranges(config_dict['iprr']):
        print('NOK.')
        print(f"Invalid IP Address range (IPRR) file {config_dict['iprr']}!")
        return
    print('OK')

    # get local network config
    print('Getting local network config ... ', end='')
    tool.get_local_network_info()
    if tool.localNetwork['ip'] and tool.localNetwork['gw'] and tool.localNetwork['dns']:
        print('OK')
    else:
        print('NOK')

    # Verify local gateway
    if tool.localNetwork['gw']:
        print('Verify default gateway ... ', end='')
        res = tool.verify_gateway()
        print('OK' if res else 'NOK')

    # Verify DNS
    print('Verifying DNS Servers ... ', end='')
    res = tool.verify_playbook_dns()
    print('OK' if res else 'NOK')

    # Verify NTP Servers
    print('Verifying NTP Servers ... ', end='')
    res = tool.verify_playbook_ntp()
    print('OK' if res else 'NOK')

    # Verify TCP and SSL streams
    tool.verify_playbook_connection()

    # Verify qbone quic connections
    tool.verify_playbook_qbone()

    # Create report
    print(f"Write report to {report_file_name} ... ", end='')
    tool.create_report()
    print('Done')

    # print(tool.results.keys())


if __name__ == '__main__':

    main()
