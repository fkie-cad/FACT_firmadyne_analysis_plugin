import pexpect
import logging
import os
from common_helper_process import execute_shell_command_get_return_code, execute_interactive_shell_command

from helper import FIRMADYNE_PATH, ResultType, change_dir_to_firmadyne_dir


def prepare_emulation(input_file, result_dict):
    result_attribute = extract_image(input_file)
    result_dict.update(result_attribute)
    logging.debug(result_attribute)
    if ResultType.FAILURE in result_attribute.values():
        return ResultType.FAILURE

    preparation_steps = [store_architecture, load_filesystem, create_qemu_image, infer_network_configuration]

    for step in preparation_steps:
        result_attribute = step()
        result_dict.update(result_attribute)
        logging.debug(result_attribute)
        if ResultType.FAILURE in result_attribute.values():
            return ResultType.FAILURE

    return ResultType.SUCCESS


def infer_network_configuration():
    try:
        child = pexpect.spawn('/bin/bash {}/scripts/inferNetwork.sh 1'.format(FIRMADYNE_PATH), timeout=80)
        child.expect('Password for user firmadyne: ')
        child.sendline('firmadyne')
        ip_address_filter = '\'[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}\'\)'
        child.expect(ip_address_filter)
        ip_address = str(child.after).split('\'')[1]
        child.wait()
        logging.debug('Infer_network IP: {}'.format(ip_address))
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
    command = 'python3 {}/sources/extractor/extractor.py -b Device -sql 127.0.0.1 -np -nk \'{}\' {}/images'.format(FIRMADYNE_PATH, input_file, FIRMADYNE_PATH)

    if not os.path.exists(input_file):
        return {'extraction': ResultType.FAILURE, 'error_message': 'Invalid path to the input file'}
    if not execute_shell_command_get_return_code(command)[1]:
        if os.path.exists(os.path.join(FIRMADYNE_PATH, 'images/1.tar.gz')):
            return {'extraction': ResultType.SUCCESS}
        return {'extraction': ResultType.FAILURE, 'error_message': 'It wasn\'t possible to extract the filesystem'}
    return {'extraction': ResultType.FAILURE, 'error_message': 'ERROR executing the extraction script'}
