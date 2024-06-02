# SSH Penetration Test Script
 SSH Penetration Test Script simulates an attacker attempting to gain unauthorized access to a target SSH server. It performs SSH login attempts using a list of users and keys, executes malicious commands on the target server, and retrieves additional SSH keys for potential access. For educational purposes only.

## How to Use

1. Add target users to the `users` file.
2. Add target SSH servers to the `hosts` file.
3. Run the script: `python "sshPenetrationTestScript.py"`

## Requirements

- Python 3.x
- SSH keys

## Sample Malicious Commands

Sample malicious commands that the script can execute include:

- System Information
- Network Information
- User Information
- File and Directory Information
- Services and Processes
- Security Information