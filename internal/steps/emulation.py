import multiprocessing
import os
import time

from common_helper_process.fail_safe_subprocess import execute_shell_command_get_return_code

from plugins.analysis.firmadyne.internal import FIRMADYNE_PATH, ResultType


def start_emulation(result_dict, emulation_init_time):
    firmware_emulation = start_emulation_process_parallel(emulation_init_time)
    network_accessibility = check_network_accessibility(result_dict['ip'])
    if not network_accessibility:
        result_dict.update({'emulation': ResultType.FAILURE, 'error_message': 'Firmadyne wasn\'t able to start the network while emulating'})
        return firmware_emulation
    result_dict.update({'emulation': ResultType.SUCCESS})
    return firmware_emulation


def start_emulation_process_parallel(emulation_init_time):
    '''emulation_process = multiprocessing.Process(name='firmware emulation', target=emulate_firmware)
    emulation_process.start()
    time.sleep(emulation_init_time)
    return emulation_process'''
    pass


def check_network_accessibility(ip_address):
    if os.system('ping -c 1 ' + ip_address) == 0:
        return 1
    else:
        return 0


def emulate_firmware():
    command = 'sudo {}/scratch/1/run.sh'.format(FIRMADYNE_PATH)
    execute_shell_command_get_return_code(command)
