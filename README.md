# ssh_logger

**WARNING**: This is still a work-in-progress.

Read a `yaml` config, and run some pre-defined commands from the config with Netflix's [`go-expect`][3].

In short, log SSH Client output; batteries included.

- Pre-scripted command configs, per-host
- Customizable CLI prompt detection
- Optionally-timestampped command logs (both UTC and local timezones)
- ping logs (requires elevated privileges)
- Server sniffer logs (requries elevated privileges)


To build the [`ssh_logger`][1] client, you need to have:

- [Go][10]
- [`ssh`][6], [`sshpass`][7]. [OpenSSH][6] is required.
- [`libpcap-dev`][8] (Unix-like OS) / [npcap][9] (Windows) installed in your operating-system

It's all wrapped into one portable binary that you can install on any number of clients; this is a key advantage of developing in [Go][10] (for instance, compared with [Python][11]).  Developing this in [Python][11] would result in a much slower runtime, the inability to reliabily sniff (because of slow execution), and you would need to download all build dependencies on every new [`ssh_logger`][1] client.

# Use case

Example of SSH into 127.0.0.1 as `mpenning`, run commands in [`configs/localhost.yaml`][2] with timestamps, and no pings:

- ` ssh_log --yaml configs/localhost.yaml --verbose`

Example of using [`configs/localhost.yaml`][2], which will SSH as `mpenning`,  run commands in [`configs/localhost.yaml`][2] with timestamps, pings, and sniffer pcaps on `eth0`:

- `sudo ssh_log --yaml configs/localhost.yaml --verbose --pingCount 10 --sniff eth0`

# YAML Configuration Help

[`ssh_logger`][1] uses a brief YAML client configuration per ssh server.

Contents of an example YAML configuration file.

```yaml
ssh_logger:
  timezone_location: "America/Chicago"
  process_loop_sleep_seconds: 5
  ssh_user: "mpenning"
  ssh_host: "localhost"
  ssh_authentication: "password"
  ssh_prompt_regex: mpenning.localhost\S+?\$
  ssh_privilege_command: "# no privilege command"
  prefix_command: "date"
  commands:
  - "ls -la | grep vim"
  - "exit"
```

- `timezone_location`: is the timezone that verbose log timestamps are rendered as (in addition to UTC).
- `process_loop_sleep_seconds`: are the number of seconds that [`ssh_logger`][1] will sleep after running all commands
- `ssh_user`: is the username that [`ssh_logger`][1] will use when logging into the SSH server
- `ssh_host`: is the SSH server DNS or IP
- `ssh_authentication` is one of several keywords:
  - `none`: No SSH server authentication is used; it's rare to use this, but a few hosts do (such as SSH to `rviews@route-views.routeviews.org`)
  - `password`: SSH Password authentication is used; for now, we assume that the Cisco IOS VTY password and Cisco IOS enable password are the same.  [`ssh_logger`][1] asks for the password at the CLI before starting.
  - `password:/path/to/ssh/privatekey`: SSH Password authentication with an SSH private key. [`ssh_logger`][1] asks for the password at the CLI before starting.
  - `key:/path/to/ssh/privatekey`: Password-less authentication with an SSH private key.
- `ssh_prompt_regex`: Use an **un-quoted** regex string to detect a prompt; more than one character can be used.
- `ssh_privilege_command`: Use an escaped-regex string for what is used to detect a prompt; more than one character can be used.
- `prefix_command`: [`ssh_logger`][1] can run commands together in pairs.  This prefix command is often used to capture a timestamp from the server (such as the unix [`date`][12] command)
- `commands`: [`ssh_logger`][1] will run this list commands on the server; if there is a `prefix_command`, it is run before every command listed here.

# CLI Help

```
$ ./ssh_logger -h
Usage of ./ssh_logger:
      --debug                      Flag to show interactive debugs of the remote host SSH session, default is False
      --failOnPingLoss             Flag to fail and exit on ping loss, default is False
      --logFilename commands.log   Name of the Netflix go-expect command logfile.  Default is commands.log (default "commands.log")
      --pingCount int              Specify the number of pings
      --pingInterval int           Specify the ping interval, in milliseconds (default 200)
      --pingSize int               Specify the ping size, in bytes (default 64)
      --sniff string               Name of interface to sniff (default "__UNDEFINED__")
      --sshKeepalive int           Specify ssh keepalive timeout, in seconds (default 60)
      --verbose                    Flag to enable verbose log timestamps, default is False
      --yaml string                Path to the YAML configuration file (default "__UNDEFINED__")
```

# Build the binary

Use [GNU `make`][5]

- `make`

or

- `go build -o ssh_logger main.go`

# Inspiration from real life

- Question: Why did you build a custom Go binary to log ssh sessions when you can simply log the output of an ssh session with the [`script`][4] command: `script -c 'ssh foo@bar' log.txt`?
- Answer: Key words above are "batteries included".  Real ssh session drops often devolve into a basket of unfun and time-consuming tasks.

Assume ssh sessions are dropping on your production database server; that's an important problem to solve, especially if the network is dropping traffic (which means your database sessions themselves are slowing down from network packet drops).

1. Most basic, why is your ssh session dropping intermittantly? Is it the network, the server, or both?
2. Since it could be the network, call the network engineer.
3. Now I also sit with a user at their desk and run pings to various network switches while we reproduce the problem.
4. Once we know how to reproduce the problem, someone will insist that I sniff it because we have to prove whether it is or is not the network.
5. Since it's a **production** database server, the aforementioned server usually does NOT have a sniffer already installed.  If we work in an ITIL environment, that requires that I file an ITIL change request, and thus more delays (up to a week?) before I can start the detailed work of solving the problem.
6. Since the packet drops are on a production database server, experience tells me this has a high likelyhood of going political unless I solve the problem rather quickly.
7. I now get to scrounge around for spare PC(s) to use as sniffers because nobody invested ahead of time in dedicated sniffer appliances; install linux on said PCs.
8. Once I have sniffer traces, the problem is not easily visible since SSH is encrypted, SSH / TCP keepalives can be intermixed with keystrokes, and TCP can batch packets together (i.e. if it uses TCP Nagle)

[`ssh_logger`][1] logs provide proactive evidence for the problem:

- Timestampped command logs, in UTC and your local timezone
- Prompt detection
- ping logs from the SSH client
- sniffer logs

# License and Copyright

- Apache 2.0 License
- Copyright David Michael Pennington, 2023

[1]: https://github.com/mpenning/ssh_logger/
[2]: https://github.com/mpenning/ssh_logger/blob/main/configs/localhost.yaml
[3]: https://github.com/Netflix/go-expect
[4]: https://linux.die.net/man/1/script
[5]: https://www.gnu.org/software/make/
[6]: https://www.openssh.com/
[7]: https://linux.die.net/man/1/sshpass
[8]: https://www.tcpdump.org/
[9]: https://npcap.com/
[10]: https://go.dev/
[11]: https://python.org/
[12]: https://linux.die.net/man/1/date
