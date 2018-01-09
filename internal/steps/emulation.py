import multiprocessing
import time
import logging
from common_helper_process.fail_safe_subprocess import execute_shell_command_get_return_code

from helper import FIRMADYNE_PATH, ResultType


def start_emulation(result_dict, emulation_init_time):
    firmware_emulation = start_emulation_process_parallel(emulation_init_time)
    network_accessibility = check_network_accessibility(result_dict['ip'])
    if not network_accessibility:
        new_ip_address = check_all_host_addresses_and_return_accessible(result_dict['ip'])
        if new_ip_address:
            result_dict.update({'emulation': ResultType.SUCCESS})
            result_dict.update({'ip': new_ip_address})
            return firmware_emulation
        result_dict.update({'emulation': ResultType.FAILURE, 'error_message': 'Firmadyne wasn\'t able to start the network while emulating'})
        return firmware_emulation
    result_dict.update({'emulation': ResultType.SUCCESS})
    return firmware_emulation


def start_emulation_process_parallel(emulation_init_time):
    emulation_process = multiprocessing.Process(name='firmware emulation', target=emulate_firmware)
    emulation_process.start()
    time.sleep(emulation_init_time)
    return emulation_process


def check_network_accessibility(ip_address):
    output, rc = execute_shell_command_get_return_code('ping -c 1 {}'.format(ip_address), timeout=5)
    logging.debug('check_network:\/n{}'.format(output))
    if rc == 0:
        return True
    else:
        return False


def check_all_host_addresses_and_return_accessible(ip_address):
    ip_without_host_part = cut_host_part_from_ip(ip_address)
    output, rc = execute_shell_command_get_return_code('fping -a -q -g {}.0/24'.format(ip_without_host_part))
    if not output:
        return output
    else:
        logging.debug('new ip with other host address is detected:{}'.format(output))
        return output.strip()


def cut_host_part_from_ip(ip_address):
    ip_components = ip_address.split('.')
    return '.'.join(ip_components[:3])


def emulate_firmware():
    logging.debug('start emulation')
    command = 'sudo {}/scratch/1/run.sh'.format(FIRMADYNE_PATH)
    output, rc = execute_shell_command_get_return_code(command)
    logging.debug('emulation output {}'.format(output))
