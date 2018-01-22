from common_helper_files.fail_safe_file_operations import get_dir_of_file
import os


FIRMADYNE_PATH = os.path.join(get_dir_of_file(__file__), '../bin/firmadyne')


class ResultType:
    SUCCESS = 'Successful'
    FAILURE = 'Failed'


def change_dir_to_firmadyne_dir():
    return os.chdir(FIRMADYNE_PATH)
