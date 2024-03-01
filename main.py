#!/usr/bin/python3

import sys
import argparse
import utils
import nmap
from ParseNmapXML import ParseNmapXML

project_data = utils.read_file('./configuration/project_data.json', 'json')
project_path = project_data['project_path'] + project_data['project_name']
scan_folder_path = project_path + '/scans/'

###
# Script Usages
###
script_args = argparse.ArgumentParser()
script_args.add_argument("--full-automatic", "-a", default=None, action="store_true", dest="fullAutomatic", help="")
args = script_args.parse_args()


###
# Initialize project
###
def full_automatic():
    try:
        # host is up ?
        utils.is_host_up(project_data.get("target_ip"))
        # Create folder structure
        utils.create_project(project_data.get('project_path'), project_data.get('project_name'))
        # Launch nmap scan
        nmap.nmap_full_scan(project_data, scan_folder_path)
        # Parse XML result
        nmap_data = ParseNmapXML(f'{ scan_folder_path }tcp_complete_scan.xml')
        # Get open ports
        open_ports = nmap_data.get_nmap_parsed_open_ports()
        open_ports_table = nmap.generate_nmap_str_table(open_ports)
        # right into report
        data = [
            {
                'nmap_scan': {
                    'regex': r'\{{2}nmap_scan\}{2}',
                    'data': utils.read_file(f'{ scan_folder_path }tcp_complete_scan.md', None)
                },
                'nmap_port_table': {
                    'regex': r'\{{2}nmap_port_table\}{2}',
                    'data': open_ports_table
                },
                'services': {
                    'regex': r'\{{2}services\}{2}',
                    'data': nmap_data.get_open_ports_list()
                }
            }
        ]

        utils.insert_data_to_report('./template/template.md', data, project_path)

    except Exception as error:
        print(f'\nAn error occurred while running full automatic scans\n{ error }')
        sys.exit(1)

    return


###
# Run program
###
if __name__ == '__main__':
    if len(sys.argv) == 1:
        script_args.print_help(sys.stderr)
        sys.exit(1)

    if args.fullAutomatic is not None:
        full_automatic()
