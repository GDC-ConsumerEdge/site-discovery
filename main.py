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
        help="playbook yaml file. Default is 'playbook.yaml' in the installation directory"
    )
    parser.add_argument(
        "-l",
        "--log_dir",
        type=str,
        help="log directory. Default is current working directory. log file name is 'site-discovery.log'"
    )
    parser.add_argument(
        "-r",
        "--report_dir",
        type=str,
        help="""report directory. Default is the current working directory.
        report file name is 'site-discovery-report_<timestamp>.txt'. timestamp = YYYYmmDD-HHMMSS"""
    )

    config_dict = {
        'playbook': os.path.join(proj_dir, 'playbook.yaml'),
        'log_dir': os.getcwd(),
        'report_dir': os.getcwd()
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
            if k == '-f':
                if os.path.isfile(arg_dict[k]):
                    config_dict['playbook'] = arg_dict[k]
            elif k == '-l':
                if os.path.isdir(arg_dict[k]):
                    config_dict['log_dir'] = arg_dict[k]
            elif k == '-r':
                if os.path.isdir(arg_dict[k]):
                    config_dict['report_dir'] = arg_dict[k]
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
    print(f'Loading Playbook {config_dict['playbook']} ...', end='')
    with open(config_dict['playbook'], 'r') as input_file:
        if not tool.load_playbook(input_file):
            print('NOK.')
            print(f"Invalid playbook YAML file {config_dict['playbook']}!")
            return
    print('OK')
    # print(tool.playbook)

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


def usage():
    usage_str = r'''
Usage:

-f: playbook yaml file. Default is 'playbook.yaml' in the installation directory
-l: log directory. Default is current working directory.
    log file name is 'site-discovery.log'
-r: report directory. Default is the current working directory.
    report file name is 'site-discovery-report_<timestamp>.txt'. timestamp = YYYYmmDD-HHMMSS'''
    print(usage_str)


if __name__ == '__main__':

    main()
