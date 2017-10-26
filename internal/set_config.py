#! /usr/bin/env python3
import argparse
import fileinput
import sys


def search_and_replace_text(input_file, search_text, replace_text):
    for line in fileinput.input(input_file, inplace=1):
        line = line.replace(search_text, replace_text)
        sys.stdout.write(line)


def parse_arguments():
    parser = argparse.ArgumentParser(description='Configuration of firmadyne.config')
    parser.add_argument('-input', action='store', dest='input')
    parser.add_argument('-firmadyne_path', action='store', dest='firmadyne_path')
    results = parser.parse_args()
    return results


def main():
    args = parse_arguments()
    input_file_path = args.input
    search_text = '#FIRMWARE_DIR=/home/vagrant/firmadyne'
    replace_text = 'FIRMWARE_DIR=' + args.firmadyne_path
    search_and_replace_text(input_file_path, search_text, replace_text)


if __name__ == '__main__':
    main()
    sys.exit()
