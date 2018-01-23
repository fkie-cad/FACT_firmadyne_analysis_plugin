import os
import gc
import pytest
from common_helper_files import get_dir_of_file

from plugins.analysis.firmadyne.internal.helper import ResultType
from plugins.analysis.firmadyne.internal.firmadyne_wrapper import clean_firmadyne, execute_firmadyne
from plugins.analysis.firmadyne.internal.steps.prepare import extract_image
from plugins.analysis.firmadyne.internal.steps.analysis import start_analysis, match_unique_exploit_log_files, get_list_of_sorted_lines_from_text_file, transform_string_of_paths_into_jstree_structure, \
    parse_logfile_list, start_nmap_analysis, start_metasploit_analysis, start_web_access_analysis, start_snmp_walk, execute_analysis_scripts
from plugins.analysis.firmadyne.internal.steps.emulation import network_is_available


TEST_FILE_PATH = os.path.join(get_dir_of_file(__file__), 'data')


def teardown_module(module):
    gc.collect()


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
    assert network_is_available(input_data) == expected


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


@pytest.mark.skip(reason='test file missing')
def test_firmadyne_scheng(self):
    file_path = '/media/firmware/firmware_files/network/lisas_firmware/RT-AC53_3.0.0.4_380_6038-g76a4aa5.trx'
    clean_firmadyne()
    status, _ = execute_firmadyne(file_path)
    assert status == ResultType.SUCCESS
