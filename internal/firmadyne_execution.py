#! /usr/bin/env python3
import argparse
from collections import OrderedDict
from common_helper_files import get_dir_of_file, get_binary_from_file
from common_helper_process import execute_shell_command_get_return_code, execute_shell_command, execute_interactive_shell_command
import json
import multiprocessing
import os
import pexpect
import re
import time
import sys


firmadyne_path = os.path.join(get_dir_of_file(__file__), '../bin/firmadyne')
firmadyne_execution_log = os.path.join(firmadyne_path, 'firmadyne_execution.log')


def firmadyne(input_file):
    execution_result, result_dict = execute_firmadyne(input_file)
    if execution_result:
        print('Firmadyne finished all Steps successfully')
        result_dict['Result'] = 'Firmadyne finished all Steps succesfully!'
    else:
        print('Firmadyne failed')
        result_dict['Result'] = 'Firmadyne failed!'
    with open('{}/results.json'.format(firmadyne_path), 'w') as result_file:
        json.dump(result_dict, result_file)


def execute_firmadyne(input_file):
    result_dict = OrderedDict()

    preparation, result_dict, ip_address = prepare_emulation(input_file, result_dict)
    if not preparation:
        return 0, result_dict

    emulation, result_dict, firmware_emulation = start_emulation(result_dict, ip_address, emulation_init_time=40)
    if not emulation:
        firmware_emulation.terminate()
        return 0, result_dict

    analysis, result_dict = start_analysis(ip_address, result_dict)
    firmware_emulation.terminate()
    if not analysis:
        return 0, result_dict

    return 1, result_dict


def start_emulation(result_dict, ip_address, emulation_init_time):
    firmware_emulation = start_emulation_process_parallel(emulation_init_time)
    network_accessibility = check_network_accessibility(ip_address)
    if not network_accessibility:
        print('Step 6 failed - Firmadyne wasn\'t able to start the network while emulating')
        result_dict.update({'STEP 6 - Emulation': 'failed : Firmadyne wasn\'t able to start the network while emulating'})
        return 0, result_dict, firmware_emulation
    print('Step 6 started - Firmadyne now is emulating the network of the Firmware')
    result_dict.update({'STEP 6 - Emulation': 'successful'})
    return 1, result_dict, firmware_emulation


def start_emulation_process_parallel(emulation_init_time):
    process_name = multiprocessing.Process(name='firmware emulation', target=emulate_firmware)
    process_name.start()
    time.sleep(emulation_init_time)
    return process_name


def prepare_emulation(input_file, result_dict):
    result_attribute = extract_image(input_file)
    result_dict.update(result_attribute)
    if not result_attribute == {'STEP 1 - Extraction': 'successful'}:
        return 0, result_dict, ''
    result_attribute = store_architecture_in_database()
    result_dict.update(result_attribute)
    if not result_attribute == {'STEP 2 - Storing Architecture': 'successful'}:
        return 0, result_dict, ''
    result_attribute = load_filesystem_into_Database()
    result_dict.update(result_attribute)
    if not result_attribute == {'STEP 3 - Load Filesystem': 'successful'}:
        return 0, result_dict, ''
    result_attribute = create_QEMU_image()
    result_dict.update(result_attribute)
    if not result_attribute == {'STEP 4 - Create QEMU Image': 'successful'}:
        return 0, result_dict, ''
    ip_address, result_attribute = infer_network_config()
    result_dict.update(result_attribute)
    if not ip_address:
        return 0, result_dict, ''

    return 1, result_dict, ip_address


def start_analysis(ip_address, result_dict):
    analysis, result_dict = execute_analysis_scripts(ip_address, result_dict)
    if not analysis:
        result_dict.update({'STEP 7 - Analysis': 'failed'})
        return 0, result_dict
    result_dict.update({'STEP 7 - Analysis': 'Done!'})
    return 1, result_dict


def check_network_accessibility(ip_address):
    if os.system('ping -c 1 ' + ip_address) == 0:
        print('The IP {} is accessible.'.format(ip_address))
        return 1
    else:
        print('The IP {} is not accessible.'.format(ip_address))
        return 0


def format_ip_for_mongo_db(ip_address):
    return ip_address.replace('.', '_')


def execute_analysis_scripts(ip_address, result_dict):
    ip_format2 = format_ip_for_mongo_db(ip_address)
    result_dict['IP'] = ip_format2

    print('STEP 7 - The Analysis will be started now')
    snmp_walk, result_attribute = start_snmp_walk(ip_address)
    result_dict['Snmp walk:'] = result_attribute
    if not snmp_walk:
        return 0, result_dict

    web_access_analysis, result_attribute = start_web_access_analysis(ip_address)
    result_dict['Accessible web files'] = result_attribute
    if not web_access_analysis:
        return 0, result_dict
    print('Metasploit Exploits will be tested now...')

    metasploit_analysis, result_attribute = start_metasploit_analysis(ip_address)
    result_dict['Metasploit Results'] = result_attribute
    if not metasploit_analysis:
        return 0, result_dict
    print('Metasploit Exploit Analysis finished.')

    nmap_analysis, result_attribute = start_nmap_analysis(ip_address)
    result_dict['Nmap Results:'] = result_attribute
    if not nmap_analysis:
        return 0, result_dict
    print('Analysis finished finished successfully')

    return 1, result_dict


# this function creates snmp.public.txt and snmp.private.txt and does not delete them
def start_snmp_walk(ip_address):
    command = '/bin/bash {}/analyses/snmpwalk.sh {}'.format(firmadyne_path, ip_address)
    if not execute_shell_command_get_return_code(command)[1]:
        return 1, 'snmpwalk was executed successfully'
    return 0, 'ERROR snmpwalk execution failed'


def start_web_access_analysis(ip_address):
    logfile_path = os.path.join(firmadyne_path, 'log.txt')
    command = 'python3 {}/analyses/webAccess.py 1 {} {}'.format(firmadyne_path, ip_address, logfile_path)

    if not execute_shell_command_get_return_code(command)[1]:
        sorted_lines = get_sorted_lines_from_text_file(logfile_path)
        list_of_jstree_dict = transform_text_into_jstree_structure(sorted_lines)
        if not list_of_jstree_dict:
            return 1, 'No accessible web files found'
        return 1, list_of_jstree_dict
    return 0, 'ERROR - Executing web access analysis failed'


def transform_text_into_jstree_structure(string):
    string_list = string.split("\n")
    list_of_jstree_dict = []
    for list_element in string_list:
        if not list_element:
            continue
        parent = "#"
        if "/" not in list_element:
            jstree_dict = {"id": list_element, "parent": parent, "text": list_element, "icon": "/static/file_icons/text.png"}
            list_of_jstree_dict.append(jstree_dict)
        if "/" in list_element:
            jstree_tree_dict = derive_jstree_tree_structure_from_path(list_element, list_of_jstree_dict, parent)
            list_of_jstree_dict = list_of_jstree_dict + jstree_tree_dict
    return list_of_jstree_dict


def derive_jstree_tree_structure_from_path(list_element, list_of_jstree_dict, parent):
    jstree_tree_list = []
    line_list = list_element.split("/")
    parent_counter = 1
    for list_element in line_list:
        jstree_dict = {"id": list_element, "parent": parent, "text": list_element}
        if parent_counter < len(line_list):
            jstree_dict.update({"icon": "/static/file_icons/folder.png"})
            parent_counter += 1
        else:
            jstree_dict.update({"icon": "/static/file_icons/text.png"})
        parent = list_element
        if jstree_dict in list_of_jstree_dict:
            continue
        jstree_tree_list.append(jstree_dict)
    return jstree_tree_list


def move_folder_strings_at_the_end(string_list):
    return sorted(string_list, key=lambda x: 1 if '/' in x else 0)


def get_sorted_lines_from_text_file(text_file_path):
    with open('{}'.format(text_file_path), 'r') as text_file:
        lines_list = text_file.readlines()
        lines_list.sort()
    separated_folder_strings = move_folder_strings_at_the_end(lines_list)
    lines = "".join(separated_folder_strings)
    return lines


def start_metasploit_analysis(ip_address):
    logfiles_dir = os.path.join(firmadyne_path, 'exploits')
    command = 'mkdir {}; python2 {}/analyses/runExploits.py -t {} -o {}/exploit -e x'.format(logfiles_dir, firmadyne_path, ip_address, logfiles_dir)
    if not execute_shell_command_get_return_code(command)[1]:
        positive_logs_list = parse_positive_metasploit_logs(logfiles_dir)
        if not positive_logs_list:
            return 1, 'No Vulnerability to the Metasploit Exploits!'
        return 1, positive_logs_list
    return 0, 'ERROR - Executing metasploit analysis failed'


def start_nmap_analysis(ip_address):
    logfile_path = os.path.join(firmadyne_path, '/nmap.log')
    command = 'sudo nmap -O -sV {} -oN {}'.format(ip_address, logfile_path)
    if not execute_shell_command_get_return_code(command)[1]:
        attribute_list = parse_log_file(logfile_path)
        if not attribute_list:
            return 0, 'ERROR - Parsing web access analysis failed'
        return 1, attribute_list
    return 0, 'ERROR - Executing nmap analysis failed'


def parse_positive_metasploit_logs(logfiles_dir):
    command = 'grep -rnw -e \'[+]\' {}'.format(logfiles_dir)
    command_stdout, return_code = execute_shell_command_get_return_code(command)
    if return_code > 0:
        return 0
    exploit_log_filename_list = match_unique_exploit_log_files(command_stdout)
    if not exploit_log_filename_list:
        return 0
    log_data_list = parse_logfile_list(exploit_log_filename_list)
    return log_data_list


def parse_logfile_list(logfile_list):
    positive_log_data = ''
    for logfile in logfile_list:
        log = parse_log_file(logfile)
        log = remove_command_literals(log)
        log = str(log) + '\n------------\n'
        if not log:
            print('Parsing logfile {} failed'.format(logfile))
            return 0
        positive_log_data += log

    return positive_log_data


def remove_command_literals(log):
    return log.replace('\x1b[1m\x1b[32m', '').replace('\x1b[0m', '').replace('\x1b[1m\x1b[34m', '')


def match_unique_exploit_log_files(string):
    match = re.findall(r'{}/exploits/exploit\.\d\d*\.log'.format(firmadyne_path), string, re.DOTALL)
    return match


def parse_log_file(log_file_path):
    return get_binary_from_file(log_file_path).decode(encoding='utf_8', errors='replace')


def emulate_firmware():
    command = 'sudo {}/scratch/1/run.sh'.format(firmadyne_path)
    execute_shell_command_get_return_code(command)


def infer_network_config():
    try:
        print('STEP 5 started...')
        child = pexpect.spawn('/bin/bash {}/scripts/inferNetwork.sh 1'.format(firmadyne_path), timeout=80)
        child.expect('Password for user firmadyne: ')
        child.sendline('firmadyne')
        # filter ip address
        child.expect('\'+[0-9]*.[0-9]*.[0-9]*.[0-9]*\'\)')
        ip_address = str(child.after).split('\'')[1]
        child.wait()
    except Exception:
        print('Error: ' + str(child))
        print('While executing the inferNetwork script an error occurred.')
        return 0, {'STEP 5 - Infer Network': 'failed: Error executing infer_network script. ' + str(child)}

    if not ip_address:
        return 0, {'STEP 5 - Infer Network': 'failed : No ip_address could be inferred'}
    print('STEP 5 has finished - The network configurations were inferred with IP {}.'.format(ip_address))
    return ip_address, {'STEP 5 - Infer Network': 'successfull'}


def create_QEMU_image():
    command = 'sudo {}/scripts/makeImage.sh 1'.format(firmadyne_path)
    execute_interactive_shell_command(command, inputs={'Password for user firmadyne: ': 'firmadyne'}, timeout=600)

    if not os.path.exists(os.path.join(firmadyne_path, 'scratch/1/image.raw')):
        print('The QEMU image couldn\'t be created.')
        return {'STEP 4 - Create QEMU Image': 'failed : It wasn\'t possible to create the QEMU image'}

    print('STEP 4 finished - The QEMU image was created.')
    return {'STEP 4 - Create QEMU Image': 'successful'}


def load_filesystem_into_Database():
    command = 'python2 {}/scripts/tar2db.py -i 1 -f {}/images/1.tar.gz'.format(firmadyne_path, firmadyne_path)
    if not execute_shell_command_get_return_code(command)[1]:
        print('STEP 3 finished - The extracted filesystem was loaded into the database.')
        return {'STEP 3 - Load Filesystem': 'successful'}
    print('An error occured while executing load_filesystem_into_Database script')
    return {'STEP 3 - Load Filesystem': 'failed : ERROR occurred while executing the load_filesystem script'}


def store_architecture_in_database():
    change_dir_to_firmadyne_dir()
    command = '/bin/bash {}/scripts/getArch.sh {}/images/1.tar.gz'.format(firmadyne_path, firmadyne_path)
    rc = execute_interactive_shell_command(command, inputs={'Password for user firmadyne: ': 'firmadyne'}, timeout=120)[1]
    if rc > 0:
        print('An error occurred while executing the getArchitecture script.')
        return {'STEP 2 - Storing Architecture': 'failed : ERROR occurred while executing the store_architecture script.'}
    print('STEP 2 finished - The getArchitecture script was executed.')
    return {'STEP 2 - Storing Architecture': 'successful'}


def extract_image(input_file):
    command = 'python3 {}/sources/extractor/extractor.py -b Netgear -sql 127.0.0.1 -np -nk \'{}\' {}/images'.format(firmadyne_path, input_file, firmadyne_path)

    if not os.path.exists(input_file):
        print('The path to the input file is invalid.')
        return {'STEP 1 - Extraction': 'failed: Ivalid path to the input file'}
    if not execute_shell_command_get_return_code(command)[1]:
        if os.path.exists(os.path.join(firmadyne_path, 'images/1.tar.gz')):
            print('STEP 1 finished - The filesystem of the Firmware was extracted successfully.')
            return {'STEP 1 - Extraction': 'successful'}
        return {'STEP 1 - Extraction': 'failed: It wasn\'t possible to extract the filesystem'}
    print('It wasn\'t possible to extract the Firmware.')
    return {'STEP 1 - Extraction': 'failed: ERROR executing the extraction script'}


def clean_firmadyne():
    change_dir_to_firmadyne_dir()
    command = 'sudo {}/scripts/delete.sh 1 >> {}\LOG.log'.format(firmadyne_path, firmadyne_path)
    output, rc = execute_interactive_shell_command(command, inputs={'Password for user firmadyne: ': 'firmadyne'}, timeout=120)
    if rc > 0:
        print('Execution Failure:\n\n{}'.format(output))
        return 0
    command = 'sudo {}/scripts/additional_delete.sh  >> {}\LOG.log'.format(firmadyne_path, firmadyne_path)
    execute_shell_command(command)
    return 1


def change_dir_to_firmadyne_dir():
    return os.chdir(firmadyne_path)


def parse_arguments():
    parser = argparse.ArgumentParser(description='Firmadyne Emulation and Analysis')
    parser.add_argument('input_file')
    results = parser.parse_args()
    return results.input_file


def main():
    input_file = parse_arguments()
    clean_firmadyne()
    firmadyne(input_file)
    clean_firmadyne()


if __name__ == '__main__':
    main()
    sys.exit()
