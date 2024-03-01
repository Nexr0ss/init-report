import os
import re
import json
import subprocess


def read_file(file_path, file_type):
    if file_exists(file_path):
        with open(file_path, "r") as file_content:
            # TODO - I dont like this naming "None" for a file
            if file_type is None:
                return file_content.read()
            else:
                match file_type:
                    case 'json':
                        return json.load(file_content)
    else:
        print(f'Could not find file : { file_path }')

        return


def is_host_up(ip):
    print("\n[+] Checking if host is up")

    try:
        is_alive = os.system("ping -c 1 " + ip + " > /dev/null 2>&1")

        if is_alive == 0:
            print(f'Host { ip } is up')
            return True
        else:
            print(f'Could not ping { ip }')
            return False
    except Exception as error:
        raise Exception(f'An error occurred while trying to ping host :\n{ error }')


def create_subprocess(comment, name, sub_args, timeout=300):
    print(f'\n[+] Starting { comment } subprocess')
    print(f'Command : { " ".join(sub_args) }\n')

    sub_process = subprocess.Popen(
        sub_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )

    try:
        stdout, stderr = sub_process.communicate(input=None, timeout=timeout)
        print(stdout)
    except Exception as error:
        print(f'\nAn error occurred in the subprocess (PID: { sub_process.pid }) :\n{ error }')
        sub_process.kill()
        if type(error).__name__ == 'TimeoutExpired' and name == 'tcpCompleteScan':
            raise

    return


def file_exists(file_path):
    return os.path.exists(file_path)


def create_project(project_path, project_name):
    folder_path = project_path + project_name
    print("\n[+] Initiate project creation :")

    try:
        if not os.path.exists(folder_path):
            # Create folders
            os.mkdir(folder_path)
            os.mkdir(folder_path + "/scans")
            os.mkdir(folder_path + "/exploits")
            os.mkdir(folder_path + "/screenshots")
            # Create file
            file = open(folder_path + "/notes.md", 'w')
            file.close()
        else:
            print("The folder already exists, aborting creation.")
            # TODO - This should be an option from user
            #shutil.rmtree(folder_path)
            return
    except Exception as error:
        raise Exception(f'Could not create project folder :\n{ error }')

    print(f'Folder { project_name } was created at { folder_path }')

    return


# Find the biggest string in data from nmap, will be used to generate proper row size from table in .md file report
def find_longest_str(headers, nmap_open_port_data):
    str_sizes = [len(max(headers, key=len))]

    for _open_port in nmap_open_port_data:
        for _attrib in _open_port:
            if len(_open_port[_attrib]) not in str_sizes:
                str_sizes.append(len(_open_port[_attrib]))

    return max(str_sizes)


def insert_data_to_report(template_path, data, project_path):
    if file_exists(template_path) is False:
        return

    # Open template
    with open(template_path, 'r+') as file:
        file_content = file.read()
        data_to_write = file_content

        for obj_name, attr in data[0].items():
            if re.search(attr['regex'], data_to_write) is not None:

                match obj_name:
                    case 'nmap_scan':
                        data_to_write = re.sub(attr['regex'], f'{ attr["data"] }', data_to_write)
                    case 'nmap_port_table':
                        data_to_write = re.sub(attr['regex'], f'{ attr["data"] }', data_to_write)
                    case 'services':
                        services_title = ''
                        for _port in attr["data"]:
                            services_title += f'\n#### tcp/{ _port }\n\n'
                        data_to_write = re.sub(attr['regex'], services_title, data_to_write)
                    case _:
                        return

    with open(f'{ project_path }/notes.md', 'w') as file:
        file.write(data_to_write)

    return
