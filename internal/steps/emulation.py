import multiprocessing
import time
import logging
from common_helper_process.fail_safe_subprocess import execute_shell_command_get_return_code, execute_shell_command

from helper import FIRMADYNE_PATH, ResultType


def start_emulation(result_dict, emulation_init_time):
    firmware_emulation = start_emulation_process_parallel(emulation_init_time)
    if not network_is_available(result_dict['ip']):
        ip_address_with_new_host = check_all_host_addresses_and_return_accessible(result_dict['ip'])
        if ip_address_with_new_host:
            result_dict.update({'emulation': ResultType.SUCCESS})
            result_dict.update({'ip': ip_address_with_new_host})
            result_dict.update({'emulation': ResultType.SUCCESS})
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


def network_is_available(ip_address):
    output, rc = execute_shell_command_get_return_code('ping -c 1 {}'.format(ip_address), timeout=5)
    logging.debug('check_network:\/n{}'.format(output))
    if rc == 0:
        return True
    else:
        return False


def check_all_host_addresses_and_return_accessible(ip_address):
    ip_without_host_part = get_subnet_prefix(ip_address)
    output = execute_shell_command('fping -a -q -g {}.0/24'.format(ip_without_host_part))
    if output != '':
        logging.debug('new ip with other host address is detected:{}'.format(output))
    return output.strip()


def get_subnet_prefix(ip_address):
    ip_address_components = ip_address.split('.')
    return '.'.join(ip_address_components[:3])


def emulate_firmware():
    logging.debug('start emulation')
    command = 'sudo {}/scratch/1/run.sh'.format(FIRMADYNE_PATH)
    output = execute_shell_command(command)
    logging.debug('emulation output {}'.format(output))
