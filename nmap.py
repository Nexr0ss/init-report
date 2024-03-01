import utils


nmap_config = utils.read_file('./configuration/nmap_scans.json', 'json')


def nmap_full_scan(project_data, scan_folder_path):
    print(f'\n[+] Starting nmap full scan')

    try:
        # TODO - For UDP scan using sudo give special permission to file, we want normal rights on the file
        for scan in nmap_config.values():
            for scan_type in list(scan):

                scan[scan_type]['commands'].extend([
                    # XML output for future parsing
                    '-oX', scan_folder_path + scan[scan_type]['file_name'] + '.xml',
                    # Classic output
                    '-oN', scan_folder_path + scan[scan_type]['file_name'] + '.md',
                    # Target
                    project_data['target_ip']
                ])

                utils.create_subprocess(
                    scan[scan_type]['comment'],
                    scan[scan_type]['name'],
                    scan[scan_type]['commands'],
                    scan[scan_type]['timeout']
                )
    except Exception:
        raise

    return


def generate_nmap_str_table(nmap_open_port_data):
    headers_name = ['Protocol', 'Port Number', 'Name', 'Production', 'Version']
    max_str_length = utils.find_longest_str(headers_name, nmap_open_port_data)
    row_end = '|\n'

    # Generate table headers
    row_title = ''
    headers_separation = ''
    for _header_name in headers_name:
        diff = (max_str_length - len(_header_name))

        if (max_str_length - len(_header_name)) < 1:
            diff = 0

        row_title += '| ' + _header_name + (' ' * (diff + 1))
        headers_separation += '|' + ('-' * (max_str_length + 2))

    row_title += row_end
    headers_separation += row_end

    # Generate table rows content
    rows_content = ''
    for _open_port in nmap_open_port_data:
        current_row = ''
        for _attrib in _open_port:
            current_row += '| ' + _open_port[_attrib] + (' ' * (max_str_length - len(_open_port[_attrib]) + 1))

        rows_content += current_row + row_end

    return row_title + headers_separation + rows_content
