from common_helper_files.fail_safe_file_operations import get_binary_from_file
from common_helper_process.fail_safe_subprocess import execute_shell_command_get_return_code
import os
import re

from helper import FIRMADYNE_PATH, ResultType


def start_analysis(result_dict):
    analysis = execute_analysis_scripts(result_dict)
    result_dict.update({'analysis': analysis})
    return analysis


def execute_analysis_scripts(result_dict):
    analysis_result = ResultType.SUCCESS

    for analysis_function in [start_snmp_walk, start_web_access_analysis, start_metasploit_analysis, start_nmap_analysis]:
        analysis_result = analysis_function(result_dict)
        if analysis_result == ResultType.FAILURE:
            break

    return analysis_result


# this function creates snmp.public.txt and snmp.private.txt and does not delete them
def start_snmp_walk(result_dict):
    command = '/bin/bash {}/analyses/snmpwalk.sh {}'.format(FIRMADYNE_PATH, result_dict['ip'])
    if not execute_shell_command_get_return_code(command)[1]:
        result_dict['snmp_walk'] = 'snmpwalk was executed successfully'
        return ResultType.SUCCESS
    return ResultType.FAILURE


def start_web_access_analysis(result_dict):
    logfile_path = os.path.join(FIRMADYNE_PATH, 'log.txt')
    command = 'python3 {}/analyses/webAccess.py 1 {} {}'.format(FIRMADYNE_PATH, result_dict['ip'], logfile_path)

    if not execute_shell_command_get_return_code(command)[1]:
        list_of_jstree_dict = transform_log_data_of_web_accessible_files_into_jstree_structure(logfile_path)
        result_dict['accessible_web_files'] = list_of_jstree_dict if list_of_jstree_dict else 'No accessible web files found'
        return ResultType.SUCCESS
    return ResultType.FAILURE


def transform_log_data_of_web_accessible_files_into_jstree_structure(logfile_path):
    sorted_lines_list = get_list_of_sorted_lines_from_text_file(logfile_path)
    sorted_lines_list = move_folder_strings_at_the_end(sorted_lines_list)
    sorted_lines = "".join(sorted_lines_list)
    list_of_jstree_dict = transform_string_of_paths_into_jstree_structure(sorted_lines)
    return list_of_jstree_dict


def transform_string_of_paths_into_jstree_structure(string):
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


def get_list_of_sorted_lines_from_text_file(text_file_path):
    with open('{}'.format(text_file_path), 'r') as text_file:
        lines_list = text_file.readlines()
        lines_list.sort()
    return lines_list


def start_metasploit_analysis(result_dict):
    logfiles_dir = os.path.join(FIRMADYNE_PATH, 'exploits')
    command = 'mkdir {}; python2 {}/analyses/runExploits.py -t {} -o {}/exploit -e x'.format(logfiles_dir, FIRMADYNE_PATH, result_dict['ip'], logfiles_dir)
    if not execute_shell_command_get_return_code(command)[1]:
        positive_logs_list = parse_positive_metasploit_logs(logfiles_dir)
        result_dict['metasploit_results'] = positive_logs_list if positive_logs_list else 'No Vulnerability to the Metasploit Exploits!'
        return ResultType.SUCCESS
    return ResultType.FAILURE


def start_nmap_analysis(result_dict):
    logfile_path = os.path.join(FIRMADYNE_PATH, '/nmap.log')
    command = 'sudo nmap -O -sV {} -oN {}'.format(result_dict['ip'], logfile_path)
    if not execute_shell_command_get_return_code(command)[1]:
        attribute_list = parse_log_file(logfile_path)
        if attribute_list:
            result_dict['nmap_results'] = attribute_list
            return ResultType.SUCCESS
    return ResultType.FAILURE


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
    match = re.findall(r'{}/exploits/exploit\.\d\d*\.log'.format(FIRMADYNE_PATH), string, re.DOTALL)
    return match


def parse_log_file(log_file_path):
    return get_binary_from_file(log_file_path).decode(encoding='utf_8', errors='replace')
