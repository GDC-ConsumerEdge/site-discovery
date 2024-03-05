import os
import sys
from datetime import datetime
from siteDiscoveryTool import SiteDiscoveryTool
from utils import *


def main():

    # Process input arguments
    proj_dir = os.path.dirname(__file__)

    config_dict = {
        'out_dir': os.getcwd(),
        'playbook': os.path.join(proj_dir, 'playbook.yaml'),
        'log_file': os.path.join(os.getcwd(), 'site_discovery.log'),
        'thread': 10
    }
    prog_args = sys.argv[1:len(sys.argv)]
    if len(prog_args):
        try:
            arg_dict = dict(zip(*[iter(prog_args)] * 2))
        except:
            print('Incorrect arguments!')
            usage()
            return
        for k in arg_dict.keys():
            if k == '-o':
                if os.path.isdir(arg_dict[k]):
                   config_dict['out_dir'] = arg_dict[k]
            elif k == '-f':
                if os.path.isfile(arg_dict[k]):
                    config_dict['playbook'] = arg_dict[k]
            elif k == '-l':
                config_dict['log_file'] = arg_dict[k]
            else:
                print(f'Unknown option {k}!')
                usage()
                return

    # Create tool instances
    tool = SiteDiscoveryTool()
    log = Logger()

    # add log file
    # t_now = datetime.now()
    # log_file_name = f"site-discovery_{t_now.strftime('%Y%m%d-%H%M%S')}.log"
    # log_file_path = os.path.join(config_dict['out_dir'], log_file_name)
    try:
        log_file = open(config_dict['log_file'], 'a')
    except:
        print(f'Failed to open log file {config_dict['log_file']}')
        return
    log.add_output(log_file)
    tool.bind_logger(log)

    # Start Execution
    log.print('='*60, timestamp=False)

    # load playbook
    log.print('Loading Playbook ...', timestamp=False)
    with open(config_dict['playbook'], 'r') as input_file:
        if not tool.load_playbook(input_file):
            log.print(f"Invalid playbook YAML file {config_dict['playbook']}!")
            return
    # print(tool.playbook)

    # get local network config
    log.print('Getting local network config ...', timestamp=False)
    tool.get_local_network_info()
    log.print(f"Local IP: {tool.localNetwork['ip']}, Gateway: {tool.localNetwork['gw']}, DNS_Server: {tool.localNetwork['dns']}")

    # Verify local gateway
    if tool.localNetwork['gw']:
        log.print('Verifying Default Gateway ...')
        res = ping_host(tool.localNetwork['gw'])
        tool.log_result(res)

    # Verify DNS
    log.print('Verifying DNS Servers ...', timestamp=False)
    tool.verify_playbook_dns()

    # Verify TCP streams
    log.print('Verifying Firewall Rules ...', timestamp=False)
    tool.verify_tcp_playbook()



def usage():
    usage_str = r'''
Usage:

-o: output directory. Default is the current working directory
-f: playbook yaml file. Default is 'playbook.yaml' in the installation directory
-l: log file name. Default is 'site_discovery.log' in current working directory'''
    print(usage_str)


if __name__ == '__main__':
    main()
