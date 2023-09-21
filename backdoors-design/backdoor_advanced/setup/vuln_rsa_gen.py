#!/usr/bin/python3
# Generate 2048-bit RSA pairs with common factors
# Usage: python3 vuln_rsa_gen.py [number-of-keypairs default: 2]

import sys
from subprocess import call
from Crypto.Util import number
from Crypto.PublicKey import RSA

NR_KEYPAIRS = 2
E = 65537

def get_rsa_components(p, q, e):
    n = p * q
    phi = (p-1) * (q-1)
    d = number.inverse(e, phi)

    return n, e, d, p, q

def main():
    global NR_KEYPAIRS

    common_factor = number.getPrime(1024)
    if len(sys.argv) > 1:
      NR_KEYPAIRS = int(sys.argv[1])

    for i in range(NR_KEYPAIRS):
      q = number.getPrime(1024)
      rsa_components = get_rsa_components(common_factor, q, E)
      private_key = RSA.construct(rsa_components, consistency_check=True)
      with open(f'./keys/{i}', 'wb') as file:
        pk_bytes = private_key.exportKey()
        file.write(pk_bytes)
      with open(f'./keys/{i}.pub', 'wb') as file:
        public_key = private_key.publickey()
        pb_bytes = public_key.export_key(format='OpenSSH')
        file.write(pb_bytes)


if __name__ == "__main__":
    main()
