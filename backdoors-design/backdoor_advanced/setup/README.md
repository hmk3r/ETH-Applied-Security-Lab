# Setup

To make the process of copying files to machines easier, you can run

```shell
  $ python3 -m http.server 8080 --bind 0.0.0.0
```

inside this directory and inside the the virtual machine do:

```shell
  $ wget http://IP:8080/FILENAME
```

## Steps

1. Generate vulnerable RSA keypairs by running(PyCryptoDome must be installed):

   ```shell
    $ python3 vuln_rsa_gen.py
   ```

2. Copy [setup-backup.sh](./setup-backup.sh), [keys/0](keys/0) and [keys/0.pub](keys/0.pub) to the backup machine, put them in the same directory and execute [setup-backup.sh](./setup-backup.sh) **AS ROOT** (don't forget to `chmod +x setup-backup.sh`)
3. Copy [setup-ca.sh](./setup-ca.sh), [keys/1](keys/1) and [keys/1.pub](keys/1.pub) to the ca machine, put them in the same directory and execute [setup-ca.sh](./setup-ca.sh) **AS ROOT** (don't forget to `chmod +x setup-ca.sh`)
4. For all other machines **EXCEPT THE WEB SERVER MACHINE**, copy [setup-all-other-except-web.sh](./setup-all-other-except-web.sh) and run **AS ROOT** (don't forget to `chmod +x setup-all-other-except-web.sh`)

## Delete files

Make sure to delete all setup files, keys, etc. from the VM. To safely delete, so that the files cannot be recovered, do:

```shell
  $ shred -vfzu FILE1 FILE2 FILE3
```
