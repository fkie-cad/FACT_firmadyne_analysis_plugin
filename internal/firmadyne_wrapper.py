#! /usr/bin/env python3
import argparse
from collections import OrderedDict
from common_helper_process import execute_shell_command_get_return_code, execute_shell_command, execute_interactive_shell_command
import json
import os
import pexpect
import sys
import logging
from common_helper_files import get_dir_of_file

INTERNAL_DIRECTORY_PATH = os.path.join(get_dir_of_file(__file__))

sys.path.append(INTERNAL_DIRECTORY_PATH)

from helper import FIRMADYNE_PATH, ResultType, change_dir_to_firmadyne_dir
from steps.analysis import start_analysis
from steps.emulation import start_emulation


def firmadyne(input_file):
    execution_result, result_dict = execute_firmadyne(input_file)
    if execution_result == ResultType.SUCCESS:
        result_dict['result'] = 'Firmadyne finished all Steps succesfully!'
    else:
        result_dict['result'] = 'Firmadyne failed!'
    with open('{}/results.json'.format(FIRMADYNE_PATH), 'w') as result_file:
        json.dump(result_dict, result_file)


def execute_firmadyne(input_file):
    result_dict = OrderedDict()

    preparation = prepare_emulation(input_file, result_dict)
    if preparation == ResultType.FAILURE:
        return ResultType.FAILURE, result_dict

    firmware_emulation = start_emulation(result_dict, emulation_init_time=40)
    if ResultType.FAILURE in result_dict.values():
        firmware_emulation.terminate()
        return ResultType.FAILURE, result_dict

    analysis = start_analysis(result_dict)
    firmware_emulation.terminate()
    if analysis == ResultType.FAILURE:
        return ResultType.FAILURE, result_dict

    return ResultType.SUCCESS, result_dict


def prepare_emulation(input_file, result_dict):
    result_attribute = extract_image(input_file)
    result_dict.update(result_attribute)
    print(result_attribute)
    if ResultType.FAILURE in result_attribute.values():
        return ResultType.FAILURE

    prepare_steps = [store_architecture, load_filesystem, create_qemu_image, infer_network_configuration]

    for step in prepare_steps:
        result_attribute = step()
        result_dict.update(result_attribute)
        print(result_attribute)
        if ResultType.FAILURE in result_attribute.values():
            return ResultType.FAILURE

    return ResultType.SUCCESS


def infer_network_configuration():
    try:
        child = pexpect.spawn('/bin/bash {}/scripts/inferNetwork.sh 1'.format(FIRMADYNE_PATH), timeout=80)
        child.expect('Password for user firmadyne: ')
        child.sendline('firmadyne')
        # filter ip address
        child.expect('\'[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}\'\)')
        ip_address = str(child.after).split('\'')[1]
        print('Infer_network output:{}\n{}'.format(child.before, child.after))
        child.wait()
        print('Infer_network IP: {}'.format(ip_address))
    except Exception:
        return {'infer_network_configuration': ResultType.FAILURE, 'error_message': 'Error executing infer_network script.\n{}'.format(str(child))}

    if not ip_address:
        return {'infer_network_configuration': ResultType.FAILURE, 'error_message': 'No ip_address could be inferred'}
    return {'infer_network_configuration': ResultType.SUCCESS, 'ip': ip_address}


def create_qemu_image():
    command = 'sudo {}/scripts/makeImage.sh 1'.format(FIRMADYNE_PATH)
    execute_interactive_shell_command(command, inputs={'Password for user firmadyne: ': 'firmadyne'}, timeout=600)

    if not os.path.exists(os.path.join(FIRMADYNE_PATH, 'scratch/1/image.raw')):
        return {'create_qemu_image': ResultType.FAILURE, 'error_message': 'It wasn\'t possible to create the QEMU image'}
    return {'create_qemu_image': ResultType.SUCCESS}


def load_filesystem():
    command = 'python2 {}/scripts/tar2db.py -i 1 -f {}/images/1.tar.gz'.format(FIRMADYNE_PATH, FIRMADYNE_PATH)
    if not execute_shell_command_get_return_code(command)[1]:
        return {'load_filesystem': ResultType.SUCCESS}
    return {'load_filesystem': ResultType.FAILURE, 'error_message': 'ERROR occurred while executing the load_filesystem script'}


def store_architecture():
    change_dir_to_firmadyne_dir()
    command = '/bin/bash {}/scripts/getArch.sh {}/images/1.tar.gz'.format(FIRMADYNE_PATH, FIRMADYNE_PATH)
    rc = execute_interactive_shell_command(command, inputs={'Password for user firmadyne: ': 'firmadyne'}, timeout=120)[1]
    if rc > 0:
        return {'store_architecture': ResultType.FAILURE, 'error_message': 'ERROR occurred while executing the store_architecture script.'}
    return {'store_architecture': ResultType.SUCCESS}


def extract_image(input_file):
    command = 'python3 {}/sources/extractor/extractor.py -b Netgear -sql 127.0.0.1 -np -nk \'{}\' {}/images'.format(FIRMADYNE_PATH, input_file, FIRMADYNE_PATH)

    if not os.path.exists(input_file):
        return {'extraction': ResultType.FAILURE, 'error_message': 'Invalid path to the input file'}
    if not execute_shell_command_get_return_code(command)[1]:
        if os.path.exists(os.path.join(FIRMADYNE_PATH, 'images/1.tar.gz')):
            return {'extraction': ResultType.SUCCESS}
        return {'extraction': ResultType.FAILURE, 'error_message': 'It wasn\'t possible to extract the filesystem'}
    return {'extraction': ResultType.FAILURE, 'error_message': 'ERROR executing the extraction script'}


def clean_firmadyne():
    change_dir_to_firmadyne_dir()
    command = 'sudo {}/scripts/delete.sh 1 >> {}\LOG.log'.format(FIRMADYNE_PATH, FIRMADYNE_PATH)
    output, rc = execute_interactive_shell_command(command, inputs={'Password for user firmadyne: ': 'firmadyne'}, timeout=120)
    if rc > 0:
        return 0
    command = 'sudo {}/scripts/additional_delete.sh  >> {}\LOG.log'.format(FIRMADYNE_PATH, FIRMADYNE_PATH)
    execute_shell_command(command)
    return 1


def parse_arguments():
    parser = argparse.ArgumentParser(description='Firmadyne Emulation and Analysis')
    parser.add_argument('input_file')
    results = parser.parse_args()
    return results.input_file


def main():
    input_file = parse_arguments()
    clean_firmadyne()
    print('input_file: {}'.format(input_file))
    firmadyne(input_file)
    clean_firmadyne()


if __name__ == '__main__':
    main()
    sys.exit()
