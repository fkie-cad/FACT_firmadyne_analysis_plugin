#! /usr/bin/env python3
from collections import OrderedDict
from common_helper_files import get_dir_of_file
import os
import unittest

from ..internal.firmadyne_execution import clean_firmadyne, extract_image, match_unique_exploit_log_files,\
    move_folder_strings_at_the_end, get_list_of_sorted_lines_from_text_file, transform_string_of_paths_into_jstree_structure,\
    parse_logfile_list, start_nmap_analysis, start_metasploit_analysis, start_web_access_analysis,\
    execute_analysis_scripts, start_snmp_walk, check_network_accessibility, start_analysis, execute_firmadyne


class TestPluginFirmadyne(unittest.TestCase):

    testfiles_path = os.path.join(get_dir_of_file(__file__), 'data')
    firmadyne_path = os.path.join(get_dir_of_file(__file__), '../bin/firmadyne')

    def test_extract_image(self):
        clean_firmadyne()
        input_dir = ''
        self.assertNotEqual(extract_image(input_dir), {'STEP 1 - Extraction': 'successful'})

        input_dir = os.path.join(self.testfiles_path, 'WNAP320 Firmware Version 2.0.3.zip')
        self.assertEqual(extract_image(input_dir), {'STEP 1 - Extraction': 'successful'})
        clean_firmadyne()

    def test_match_unique_exploit_logs(self):
        string = ''
        self.assertEqual(match_unique_exploit_log_files(string), [])
        string = 'aaaaaaaaa'
        self.assertEqual(match_unique_exploit_log_files(string), [])

    def test_parse_logfile_list(self):
        log_list = []
        self.assertEqual(parse_logfile_list(log_list), '')
        log_list = [os.path.join(self.testfiles_path, 'two_lines')]
        self.assertEqual(parse_logfile_list(log_list), 'hallo\nwelt\n------------\n')
        log_list = [os.path.join(self.testfiles_path, 'exploit.64.log')]
        self.assertEqual(parse_logfile_list(log_list), '[*] Spooling to file /home/bad-fw/git/faf/src/bin/firmadyne/exploits/exploit.64.log...\nresource (script.rc)> use auxiliary/scanner/ssl/openssl_ccs\nresource (script.rc)> exploit -z\n[+] 192.168.0.100:443     - No alert after invalid CCS message, probably vulnerable\n[*] 192.168.0.100:443     - Scanned 1 of 1 hosts (100% complete)\n[*] Auxiliary module execution completed\nresource (script.rc)> spool off\n\n------------\n')

    def test_move_folder_strings_at_the_end(self):
        string_list = ["a/b/c", "a", "b/a", "y", "d/", "d", "a/b/x", "u"]
        desired_output_list = ["a", "y", "d", "u", "a/b/c", "b/a", "d/", "a/b/x"]
        self.assertEqual(move_folder_strings_at_the_end(string_list), desired_output_list)

    def test_sort_lines_of_text_file(self):
        text_file_path = os.path.join(self.testfiles_path, 'log.txt')
        sorted_lines = get_list_of_sorted_lines_from_text_file(text_file_path)
        self.assertEqual(sorted_lines, "BackupConfig.php\nUserGuide.html\nbackground.html\nabc/a.txt\n")

    def test_transform_text_into_jstree_structure(self):
        input_sample = "test1.txt\netc/sub_folder/sub_sub_folder\netc/sub_folder2"
        self.assertEqual(transform_string_of_paths_into_jstree_structure(input_sample), [{"parent": "#", "id": "test1.txt", "text": "test1.txt", "icon": "/static/file_icons/text.png"},
                                                                                         {"parent": "#", "id": "etc", "text": "etc", "icon": "/static/file_icons/folder.png"},
                                                                                         {"parent": "etc", "id": "sub_folder", "text": "sub_folder", "icon": "/static/file_icons/folder.png"},
                                                                                         {"parent": "sub_folder", "id": "sub_sub_folder", "text": "sub_sub_folder", "icon": "/static/file_icons/text.png"},
                                                                                         {"parent": "etc", "id": "sub_folder2", "text": "sub_folder2", "icon": "/static/file_icons/text.png"}])

    def test_start_nmap_analysis(self):
        ip_address = ''
        self.assertEqual(start_nmap_analysis(ip_address)[0], 1)
        ip_address = '88'
        self.assertEqual(start_nmap_analysis(ip_address)[0], 1)

    def test_start_metasploit_analysis(self):
        clean_firmadyne()
        ip_adress = ''
        self.assertEqual(start_metasploit_analysis(ip_adress)[0], 1)
        ip_adress = '88'
        self.assertEqual(start_metasploit_analysis(ip_adress)[0], 1)

    def test_start_web_access_analysis(self):
        ip_address = ''
        self.assertEqual(start_web_access_analysis(ip_address)[0], 0)
        ip_address = '88'
        self.assertEqual(start_web_access_analysis(ip_address)[0], 1)
        ip_address = '127.0.0.1'
        self.assertEqual(start_web_access_analysis(ip_address)[0], 1)

    def test_start_snmp_walk(self):
        ip_address = ''
        self.assertEqual(start_snmp_walk(ip_address)[0], 1)
        ip_address = '88'
        self.assertEqual(start_snmp_walk(ip_address)[0], 1)

    def test_execute_analysis_scripts(self):
        ip_address = ''
        self.assertEqual(execute_analysis_scripts(ip_address, {})[0], 0)

    def test_check_network_accessibility(self):
        ip_address = ''
        self.assertEqual(check_network_accessibility(ip_address), 0)
        ip_address = 'aaa'
        self.assertEqual(check_network_accessibility(ip_address), 0)
        ip_address = '127.0.0.1'
        self.assertEqual(check_network_accessibility(ip_address), 1)

    def test_start_analysis(self):
        ip_address = '127.0.0.1'
        result_dict = OrderedDict()
        self.assertEqual(start_analysis(ip_address, result_dict)[0], 1)

    def test_clean_firmadyne(self):
        self.assertEqual(clean_firmadyne(), 1)

    def test_execute_firmadyne(self):
        clean_firmadyne()
        input_file = os.path.join(self.testfiles_path, 'WNAP320 Firmware Version 2.0.3.zip')
        self.assertEqual(execute_firmadyne(input_file)[0], 1)
        clean_firmadyne()
