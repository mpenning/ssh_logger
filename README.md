# ssh_logger

**WARNING**: This is still a work-in-progress.

Read a `yaml` config, and run some pre-defined commands from the config with Netflix's [`go-expect`][3].

In short, log ssh session command output; batteries included.

- Pre-scripted command configs, per-host
- Customizable CLI prompt detection
- Optionally-timestampped command logs (both UTC and local timezones)
- ping logs (requires root)
- Server sniffer logs (requries root)

You need to have `ssh` and `sshpass` installed in your operating-system.

Pinging and sniffing require root privileges.

## Use case

Example of logging into a localhost (running linux) as `mpenning`, run `ls -la | grep vim` with command timestamps, and no pings:

- ` ssh_log --yaml configs/localhost.yaml --verbose`

Example of using [`configs/localhost.yaml`][2], which will login to localhost as `mpenning`,  run `ls -la | grep vim` with command timestamps, pings, and sniffer pcaps on `eth0`:

- `sudo ssh_log --yaml configs/localhost.yaml --verbose --pingCount 10 --sniff eth0`

Output of [`configs/localhost.yaml`][2]:

```yaml
ssh_logger:
  timezone_location: America/Chicago
  process_loop_sleep_seconds: 5
  ssh_user: mpenning
  ssh_host: localhost
  ssh_authentication: password
  ssh_prompt_regex: \$
  ssh_enable_command: enable
  prefix_command: date
  commands:
  - ls -la | grep vim
  - exit
```

## Help

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

## Build the binary

Use

- `make`

or

- `go build -o ssh_logger main.go`

## Inspiration from real life

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
- ping logs from the server
- sniffer logs

## License and Copyright

- Apache 2.0 License
- Copyright David Michael Pennington, 2023

[1]: https://github.com/mpenning/ssh_logger/
[2]: https://github.com/mpenning/ssh_logger/blob/main/configs/localhost.yaml
[3]: https://github.com/Netflix/go-expect
[4]: https://man.freebsd.org/cgi/man.cgi?script(1)

