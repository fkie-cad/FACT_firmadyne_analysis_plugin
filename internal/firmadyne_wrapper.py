#! /usr/bin/env python3
import argparse
from collections import OrderedDict
from common_helper_process import execute_shell_command, execute_interactive_shell_command
import json
import os

import sys
import logging
from common_helper_files import get_dir_of_file

INTERNAL_DIRECTORY_PATH = os.path.join(get_dir_of_file(__file__))

sys.path.append(INTERNAL_DIRECTORY_PATH)

from helper import FIRMADYNE_PATH, ResultType, change_dir_to_firmadyne_dir
from steps.prepare import prepare_emulation
from steps.emulation import start_emulation
from steps.analysis import start_analysis


PROGRAM_NAME = 'Firmadyne Wrapper'
PROGRAM_VERSION = '0.4'
PROGRAM_DESCRIPTION = 'Automates firmadyne execution and stores result as json file'


def run_firmadyne_and_store_result(input_file, result_file_path):
    execution_result, result_dict = execute_firmadyne(input_file)
    if execution_result == ResultType.SUCCESS:
        result_dict['result'] = 'Firmadyne finished all Steps succesfully!'
    else:
        result_dict['result'] = 'Firmadyne failed!'
    with open(result_file_path, 'w') as result_file:
        json.dump(result_dict, result_file)


def execute_firmadyne(input_file):
    result_dict = {}

    preparation = prepare_emulation(input_file, result_dict)
    if preparation == ResultType.FAILURE:
        return ResultType.FAILURE, result_dict

    firmware_emulation = start_emulation(result_dict, emulation_init_time=40)
    if ResultType.FAILURE in result_dict.values():
        firmware_emulation.terminate()
        return ResultType.FAILURE, result_dict

    analysis = start_analysis(result_dict)
    if analysis == ResultType.FAILURE:
        return ResultType.FAILURE, result_dict

    firmware_emulation.terminate()
    return ResultType.SUCCESS, result_dict


def clean_firmadyne():
    change_dir_to_firmadyne_dir()
    command = 'sudo {}/scripts/delete.sh 1 >> {}\LOG.log'.format(FIRMADYNE_PATH, FIRMADYNE_PATH)
    _, rc = execute_interactive_shell_command(command, inputs={'Password for user firmadyne: ': 'firmadyne'}, timeout=120)
    if rc > 0:
        return 0
    command = 'sudo {}/scripts/additional_delete.sh  >> {}\LOG.log'.format(FIRMADYNE_PATH, FIRMADYNE_PATH)
    execute_shell_command(command)
    return 1


def _setup_logging(args):
    log_format = logging.Formatter(fmt='[%(asctime)s][%(module)s][%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logger = logging.getLogger('')
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    console_logger = logging.StreamHandler()
    console_logger.setFormatter(log_format)
    logger.addHandler(console_logger)


def _setup_argparser():
    parser = argparse.ArgumentParser(description='{} - {}'.format(PROGRAM_NAME, PROGRAM_DESCRIPTION))
    parser.add_argument('-V', '--version', action='version', version='{} {}'.format(PROGRAM_NAME, PROGRAM_VERSION))
    parser.add_argument('-d', '--debug', action='store_true', default=False, help='print debug messages')
    parser.add_argument('-o', '--output_file', default='{}/results.json'.format(FIRMADYNE_PATH), help='result storage path')
    parser.add_argument('input_file')
    return parser.parse_args()


def main():
    args = _setup_argparser()
    _setup_logging(args)
    clean_firmadyne()
    logging.info('Execute Firmadyne on: {}'.format(args.input_file))
    logging.debug('result storage: {}'.format(args.output_file))
    run_firmadyne_and_store_result(args.input_file, args.output_file)
    clean_firmadyne()


if __name__ == '__main__':
    main()
    sys.exit()
