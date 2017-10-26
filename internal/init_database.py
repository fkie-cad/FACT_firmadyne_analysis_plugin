#! /usr/bin/env python3
import pexpect
import sys


def create_database():
    command = 'sudo -u postgres createuser -P firmadyne'
    try:
        child = pexpect.spawn(command, timeout=10)
        i = child.expect(['Enter password for new role: ', pexpect.EOF])
        if i == 0:
            child.sendline('firmadyne')
        i = child.expect(['Enter it again: ', pexpect.EOF])
        if i == 0:
            child.sendline('firmadyne')
            child.wait()
        return 1, ''
    except Exception as e:
        print('Error:{} - {}'.format(e, str(child)))
        print('\'{}\' failed'.format(command))
        return 0, 'ERROR:' + str(child)


if __name__ == '__main__':
    create_database()
    sys.exit()
