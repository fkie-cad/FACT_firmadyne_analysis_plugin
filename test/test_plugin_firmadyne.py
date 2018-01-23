import os
import pytest
from common_helper_files import get_dir_of_file

from plugins.analysis.firmadyne.internal.helper import ResultType
from plugins.analysis.firmadyne.internal.firmadyne_wrapper import clean_firmadyne, execute_firmadyne
from plugins.analysis.firmadyne.internal.steps.prepare import extract_image
from plugins.analysis.firmadyne.internal.steps.analysis import start_analysis, match_unique_exploit_log_files, get_list_of_sorted_lines_from_text_file, transform_string_of_paths_into_jstree_structure, \
    parse_logfile_list, start_nmap_analysis, start_metasploit_analysis, start_web_access_analysis, start_snmp_walk, execute_analysis_scripts
from plugins.analysis.firmadyne.internal.steps.emulation import check_network_accessibility, cut_host_part_from_ip, check_all_host_addresses_and_return_accessible


TEST_FILE_PATH = os.path.join(get_dir_of_file(__file__), 'data')


@pytest.mark.parametrize('input_data, expected', [
    ('', 'Failed'),
    (os.path.join(TEST_FILE_PATH, 'WNAP320 Firmware Version 2.0.3.zip'), 'Successful')
])
def test_extract_image(input_data, expected):
    clean_firmadyne()
    result = extract_image(input_data)
    assert result['extraction'] == expected
    clean_firmadyne()


# test parameter meaningful?
@pytest.mark.parametrize('input_data, expected', [
    ('', []),
    ('aaaaaaaaa', [])
])
def test_match_unique_exploit_logs(input_data, expected):
    assert match_unique_exploit_log_files(input_data) == expected


@pytest.mark.parametrize('input_data, expected', [
    ([], ''),
    ([os.path.join(TEST_FILE_PATH, 'two_lines')], 'hallo\nwelt\n------------\n'),
    ([os.path.join(TEST_FILE_PATH, 'exploit.64.log')], '[*] Spooling to file /home/bad-fw/git/faf/src/bin/firmadyne/exploits/exploit.64.log...\nresource (script.rc)> use auxiliary/scanner/ssl/openssl_ccs\nresource (script.rc)> exploit -z\n[+] 192.168.0.100:443     - No alert after invalid CCS message, probably vulnerable\n[*] 192.168.0.100:443     - Scanned 1 of 1 hosts (100% complete)\n[*] Auxiliary module execution completed\nresource (script.rc)> spool off\n\n------------\n')
])
def test_parse_logfile_list(input_data, expected):
    assert parse_logfile_list(input_data) == expected


def test_sort_lines_of_text_file():
    text_file_path = os.path.join(TEST_FILE_PATH, 'log.txt')
    sorted_lines = get_list_of_sorted_lines_from_text_file(text_file_path)
    assert sorted_lines == ["BackupConfig.php\n", "UserGuide.html\n", "abc/a.txt\n", "background.html\n"]


def test_transform_text_into_jstree_structure():
    input_sample = 'test1.txt\netc/sub_folder/sub_sub_folder\netc/sub_folder2'
    assert transform_string_of_paths_into_jstree_structure(input_sample) == [
        {'parent': '#', 'id': 'test1.txt', 'text': 'test1.txt', 'icon': '/static/file_icons/text.png'},
        {'parent': '#', 'id': 'etc', 'text': 'etc', 'icon': '/static/file_icons/folder.png'},
        {'parent': 'etc', 'id': 'sub_folder', 'text': 'sub_folder', 'icon': '/static/file_icons/folder.png'},
        {'parent': 'sub_folder', 'id': 'sub_sub_folder', 'text': 'sub_sub_folder', 'icon': '/static/file_icons/text.png'},
        {'parent': 'etc', 'id': 'sub_folder2', 'text': 'sub_folder2', 'icon': '/static/file_icons/text.png'}
    ]


# test parameter meaningful?
@pytest.mark.parametrize('input_data, expected', [
    ('', ResultType.SUCCESS),
    ('88', ResultType.SUCCESS)
])
def test_analysis_nmap(input_data, expected):
    result_dict = {'ip': input_data}
    assert start_nmap_analysis(result_dict) == expected


# test parameter meaningful?
@pytest.mark.parametrize('input_data, expected', [
    ('', ResultType.SUCCESS),
    ('88', ResultType.SUCCESS)
])
def test_analysis_snmp(input_data, expected):
    result_dict = {'ip': input_data}
    assert start_snmp_walk(result_dict) == expected


# test parameter meaningful?
@pytest.mark.parametrize('input_data, expected', [
    ('', ResultType.FAILURE),
    ('88', ResultType.SUCCESS),
    ('127.0.0.1', ResultType.SUCCESS)
])
def test_analysis_web_access(input_data, expected):
    result_dict = {'ip': input_data}
    assert start_web_access_analysis(result_dict) == expected


# test parameter meaningful?
@pytest.mark.skip(reason="too slow")
@pytest.mark.parametrize('input_data, expected', [
    ('', ResultType.SUCCESS),
    ('88', ResultType.SUCCESS)
])
def test_analysis_metasploit(input_data, expected):
    clean_firmadyne()
    result_dict = {'ip': input_data}
    assert start_metasploit_analysis(result_dict) == expected


# test parameter meaningful?
@pytest.mark.parametrize('input_data, expected', [
    ('', 0),
    ('aaa', 0),
    ('127.0.0.1', 1)
])
def test_check_network_accessibility(input_data, expected):
    assert check_network_accessibility(input_data) == expected


@pytest.mark.parametrize('input_data, expected', [
    ('127.0.0.1', '127.0.0.1\n127.0.0.2\n127.0.0.3\n127.0.0.4\n127.0.0.5\n127.0.0.6\n127.0.0.7\n127.0.0.8\n127.0.0.9\n'
                  '127.0.0.10\n127.0.0.11\n127.0.0.12\n127.0.0.13\n127.0.0.14\n127.0.0.15\n127.0.0.16\n127.0.0.17\n'
                  '127.0.0.18\n127.0.0.19\n127.0.0.20\n127.0.0.21\n127.0.0.22\n127.0.0.23\n127.0.0.24\n127.0.0.25\n'
                  '127.0.0.26\n127.0.0.27\n127.0.0.28\n127.0.0.29\n127.0.0.30\n127.0.0.31\n127.0.0.32\n127.0.0.33\n'
                  '127.0.0.34\n127.0.0.35\n127.0.0.36\n127.0.0.37\n127.0.0.38\n127.0.0.39\n127.0.0.40\n127.0.0.41\n'
                  '127.0.0.42\n127.0.0.43\n127.0.0.44\n127.0.0.45\n127.0.0.46\n127.0.0.47\n127.0.0.48\n127.0.0.49\n'
                  '127.0.0.50\n127.0.0.51\n127.0.0.52\n127.0.0.53\n127.0.0.54\n127.0.0.55\n127.0.0.56\n127.0.0.57\n'
                  '127.0.0.58\n127.0.0.59\n127.0.0.60\n127.0.0.61\n127.0.0.62\n127.0.0.63\n127.0.0.64\n127.0.0.65\n'
                  '127.0.0.66\n127.0.0.67\n127.0.0.68\n127.0.0.69\n127.0.0.70\n127.0.0.71\n127.0.0.72\n127.0.0.73\n'
                  '127.0.0.74\n127.0.0.75\n127.0.0.76\n127.0.0.77\n127.0.0.78\n127.0.0.79\n127.0.0.80\n127.0.0.81\n'
                  '127.0.0.82\n127.0.0.83\n127.0.0.84\n127.0.0.85\n127.0.0.86\n127.0.0.87\n127.0.0.88\n127.0.0.89\n'
                  '127.0.0.90\n127.0.0.91\n127.0.0.92\n127.0.0.93\n127.0.0.94\n127.0.0.95\n127.0.0.96\n127.0.0.97\n'
                  '127.0.0.98\n127.0.0.99\n127.0.0.100\n127.0.0.101\n127.0.0.102\n127.0.0.103\n127.0.0.104\n'
                  '127.0.0.105\n127.0.0.106\n127.0.0.107\n127.0.0.108\n127.0.0.109\n127.0.0.110\n127.0.0.111\n'
                  '127.0.0.112\n127.0.0.113\n127.0.0.114\n127.0.0.115\n127.0.0.116\n127.0.0.117\n127.0.0.118\n'
                  '127.0.0.119\n127.0.0.120\n127.0.0.121\n127.0.0.122\n127.0.0.123\n127.0.0.124\n127.0.0.125\n'
                  '127.0.0.126\n127.0.0.127\n127.0.0.128\n127.0.0.129\n127.0.0.130\n127.0.0.131\n127.0.0.132\n'
                  '127.0.0.133\n127.0.0.134\n127.0.0.135\n127.0.0.136\n127.0.0.137\n127.0.0.138\n127.0.0.139\n'
                  '127.0.0.140\n127.0.0.141\n127.0.0.142\n127.0.0.143\n127.0.0.144\n127.0.0.145\n127.0.0.146\n'
                  '127.0.0.147\n127.0.0.148\n127.0.0.149\n127.0.0.150\n127.0.0.151\n127.0.0.152\n127.0.0.153\n'
                  '127.0.0.154\n127.0.0.155\n127.0.0.156\n127.0.0.157\n127.0.0.158\n127.0.0.159\n127.0.0.160\n'
                  '127.0.0.161\n127.0.0.162\n127.0.0.163\n127.0.0.164\n127.0.0.165\n127.0.0.166\n127.0.0.167\n'
                  '127.0.0.168\n127.0.0.169\n127.0.0.170\n127.0.0.171\n127.0.0.172\n127.0.0.173\n127.0.0.174\n'
                  '127.0.0.175\n127.0.0.176\n127.0.0.177\n127.0.0.178\n127.0.0.179\n127.0.0.180\n127.0.0.181\n'
                  '127.0.0.182\n127.0.0.183\n127.0.0.184\n127.0.0.185\n127.0.0.186\n127.0.0.187\n127.0.0.188\n'
                  '127.0.0.189\n127.0.0.190\n127.0.0.191\n127.0.0.192\n127.0.0.193\n127.0.0.194\n127.0.0.195\n'
                  '127.0.0.196\n127.0.0.197\n127.0.0.198\n127.0.0.199\n127.0.0.200\n127.0.0.201\n127.0.0.202\n'
                  '127.0.0.203\n127.0.0.204\n127.0.0.205\n127.0.0.206\n127.0.0.207\n127.0.0.208\n127.0.0.209\n'
                  '127.0.0.210\n127.0.0.211\n127.0.0.212\n127.0.0.213\n127.0.0.214\n127.0.0.215\n127.0.0.216\n'
                  '127.0.0.217\n127.0.0.218\n127.0.0.219\n127.0.0.220\n127.0.0.221\n127.0.0.222\n127.0.0.223\n'
                  '127.0.0.224\n127.0.0.225\n127.0.0.226\n127.0.0.227\n127.0.0.228\n127.0.0.229\n127.0.0.230\n'
                  '127.0.0.231\n127.0.0.232\n127.0.0.233\n127.0.0.234\n127.0.0.235\n127.0.0.236\n127.0.0.237\n'
                  '127.0.0.238\n127.0.0.239\n127.0.0.240\n127.0.0.241\n127.0.0.242\n127.0.0.243\n127.0.0.244\n'
                  '127.0.0.245\n127.0.0.246\n127.0.0.247\n127.0.0.248\n127.0.0.249\n127.0.0.250\n127.0.0.251\n'
                  '127.0.0.252\n127.0.0.253\n127.0.0.254')
])
def test_check_all_host_addresses_and_return_accessible(input_data, expected):
    assert check_all_host_addresses_and_return_accessible(input_data) == expected


@pytest.mark.parametrize('input_data, expected', [
    ('192.168.1.0', '192.168.1')
])
def test_cut_host_part_from_ip(input_data, expected):
    assert cut_host_part_from_ip(input_data) == expected


def test_execute_analysis_scripts():
    assert execute_analysis_scripts({'ip': ''}) == ResultType.FAILURE


@pytest.mark.skip(reason="too slow")
def test_start_analysis():
    result_dict = {'ip': '127.0.0.1'}
    assert start_analysis(result_dict) == ResultType.SUCCESS


def test_clean_firmadyne():
    assert clean_firmadyne() == 1


def test_execute_firmadyne():
    clean_firmadyne()
    input_file = os.path.join(TEST_FILE_PATH, 'WNAP320 Firmware Version 2.0.3.zip')
    assert execute_firmadyne(input_file)[0], ResultType.SUCCESS
    clean_firmadyne()


def test_execute_firmadyne_with_fping():
    clean_firmadyne()
    input_file = os.path.join(TEST_FILE_PATH, 'Archer C1200(EU)_V1_160918.zip')
    assert execute_firmadyne(input_file)[0], ResultType.SUCCESS
    clean_firmadyne()


@pytest.mark.skip(reason='test file missing')
def test_firmadyne_scheng(self):
    file_path = '/media/firmware/firmware_files/network/lisas_firmware/RT-AC53_3.0.0.4_380_6038-g76a4aa5.trx'
    clean_firmadyne()
    status, result = execute_firmadyne(file_path)
    assert status == ResultType.SUCCESS
