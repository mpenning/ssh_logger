package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	// logoru provides fancy logging similar to python loguru
	"github.com/gleich/logoru"
	// pflag is a drop-in replacement for the golang CLI `flag` package
	"github.com/spf13/pflag"
	// viper is a multi-lingual config-reader: toml, ini, json, etc...
	"github.com/spf13/viper"
	// Use this to read the password from the terminal
	"golang.org/x/crypto/ssh/terminal"

	// Netflix go-expect provides a golang Expect library...
	expect "github.com/Netflix/go-expect"
	// pro-bing is an intelligent ping library from Prometheus...
	probing "github.com/prometheus-community/pro-bing"
	// gopacket requires libpcap-dev
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type cliOpts struct {
	commandLogFilename string
	yaml               string
	sniff              string
	sshKeepalive       int
	pingCount          int
	pingInterval       int
	pingSizeBytes      int
	failOnPingLoss     bool
	debug              bool
	verboseTime        bool
}

type yamlConfig struct {
	tzLocation          string
	sshUser             string
	sshHost             string
	sshAuthentication   string
	sshPassword         string
	sshPromptRegex      string
	sshLoopSleepSeconds int
	sshPrivilegeCmd     string
	prefixCmd           string
	commands            []string
}

func main() {

	////////////////////////////////////////////////////////////////////////////
	// parse CLI flags here
	////////////////////////////////////////////////////////////////////////////
	commandLogFilenamePtr := pflag.String("logFilename", "commands.log", "Name of the Netflix go-expect command logfile.  Default is `commands.log`")
	sniffPtr := pflag.String("sniff", "__UNDEFINED__", "Name of interface to sniff")
	yamlPtr := pflag.String("yaml", "__UNDEFINED__", "Path to the YAML configuration file")
	sshKeepalivePtr := pflag.Int("sshKeepalive", 60, "Specify ssh keepalive timeout, in seconds")
	pingCountPtr := pflag.Int("pingCount", 0, "Specify the number of pings")
	pingIntervalPtr := pflag.Int("pingInterval", 200, "Specify the ping interval, in milliseconds")
	pingSizeBytesPtr := pflag.Int("pingSize", 64, "Specify the ping size, in bytes")

	failOnPingLossPtr := pflag.Bool("failOnPingLoss", false, "Flag to fail and exit on ping loss, default is False")
	debugPtr := pflag.Bool("debug", false, "Flag to show interactive debugs of the remote host SSH session, default is False")
	verboseTimePtr := pflag.Bool("verbose", false, "Flag to enable verbose log timestamps, default is False")
	pflag.Parse()

	if *yamlPtr == "__UNDEFINED__" {
		logoru.Critical("A yaml configuration file is required")
	}

	opts := cliOpts{
		commandLogFilename: *commandLogFilenamePtr,
		yaml:               *yamlPtr,
		sshKeepalive:       *sshKeepalivePtr,
		sniff:              *sniffPtr,
		pingCount:          *pingCountPtr,
		pingInterval:       *pingIntervalPtr,
		pingSizeBytes:      *pingSizeBytesPtr,
		failOnPingLoss:     *failOnPingLossPtr,
		debug:              *debugPtr,
		verboseTime:        *verboseTimePtr,
	}

	////////////////////////////////////////////////////////////////////////////
	// Create application config directories
	////////////////////////////////////////////////////////////////////////////
	relative_path := filepath.Join("configs")
	err := os.MkdirAll(relative_path, os.ModePerm)
	if err != nil {
		logoru.Critical(err)
	}

	// The 'os/user' package allows us to get a relative path, and also the home
	// directory
	currentDir, err := user.Current()
	if err != nil {
		logoru.Critical(err)
	}
	// Use '~/.ssh_logger/configs/' as a possible location for all configurations
	homePath := filepath.Join(currentDir.HomeDir, ".ssh_logger", "configs")
	err = os.MkdirAll(homePath, os.ModePerm)
	if err != nil {
		logoru.Critical(err)
	}

	////////////////////////////////////////////////////////////////////////////
	// Initial YAML-file support here
	////////////////////////////////////////////////////////////////////////////
	configReader := viper.New()
	configReader.AddConfigPath(".") // read CLI paths relative to this directory
	configReader.AddConfigPath("/") // read CLI absolute paths
	// for Cisco IOS (and other vendor) commands, yaml markup is
	// superior to ini markup.
	configReader.SetConfigName(opts.yaml)
	configReader.SetConfigType("yaml")
	err = configReader.ReadInConfig()
	if err != nil {
		logoru.Critical(err)
	}
	// Read the slice of commands listed under the ssh_logger / commands keys...
	locationStr := configReader.GetString("ssh_logger.timezone_location")
	sshUser := configReader.GetString("ssh_logger.ssh_user")
	sshHost := configReader.GetString("ssh_logger.ssh_host")
	sshAuthentication := configReader.GetString("ssh_logger.ssh_authentication")
	sshPromptRegex := configReader.GetString("ssh_logger.ssh_prompt_regex")
	sshLoopSleepSeconds := configReader.GetInt("ssh_logger.ssh_loop_sleep_seconds")
	// There is no support for SSH Enable (i.e. from Cisco IOS) yet...
	sshPrivilegeCmd := configReader.GetString("ssh_logger.ssh_privilege_command")
	prefixCmd := configReader.GetString("ssh_logger.prefix_command")
	myCommands := configReader.GetStringSlice("ssh_logger.commands")

	/////////////////////////////////////////////////////////////////////////////
	// Read the SSH password if the YAML config asks for password authentication
	/////////////////////////////////////////////////////////////////////////////
	var password string
	// process 'password' or 'password:/path/to/ssh/privatekey'
	if len(sshAuthentication) >= 8 {
		if sshAuthentication[0:8] == "password" {
			// for now, assume the line and privilege password are the same
			fmt.Print("Enter SSH line and privilege password: ")
			// ReadPassword() returns a slice of bytes, not a string
			passwordBytes, err := terminal.ReadPassword(0)
			if err != nil {
				logoru.Critical(err)
			}
			password = string(passwordBytes)
			fmt.Println("") // send a newline to stdout
		} else {
			password = ""
		}
	} else {
		password = ""
	}

	config := yamlConfig{
		tzLocation:          locationStr,
		sshUser:             sshUser,
		sshHost:             sshHost,
		sshAuthentication:   sshAuthentication,
		sshPassword:         password,
		sshPromptRegex:      sshPromptRegex,
		sshLoopSleepSeconds: sshLoopSleepSeconds,
		sshPrivilegeCmd:     sshPrivilegeCmd,
		prefixCmd:           prefixCmd,
		commands:            myCommands,
	}

	////////////////////////////////////////////////////////////////////////////
	// run in an infinite loop unless sshLoopSleepSeconds is 0
	////////////////////////////////////////////////////////////////////////////
	ii := 0
	for {
		logoru.Debug(fmt.Sprintf("Starting SSH loop idx: %v", ii))
		sshLoopSleepSeconds = sshLoginSession(opts, config)
		if sshLoopSleepSeconds == 0 {
			break
		} else {
			logoru.Debug(fmt.Sprintf("Continue SSH loop, sleeping %v seconds", sshLoopSleepSeconds))
			time.Sleep(time.Duration(time.Duration(sshLoopSleepSeconds) * time.Second))
			ii++
		}
	}
}

func sshLoginSession(opts cliOpts, config yamlConfig) int {

	sshAuthentication := config.sshAuthentication
	sshPromptRegex := config.sshPromptRegex
	sshLoopSleepSeconds := config.sshLoopSleepSeconds
	sshPrivilegeCmd := config.sshPrivilegeCmd
	prefixCmd := config.prefixCmd
	myCommands := config.commands

	/////////////////////////////////////////////////////////////////////////////
	// Open a new SSH command log file here
	/////////////////////////////////////////////////////////////////////////////
	logFile, err := os.OpenFile(opts.commandLogFilename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		logoru.Critical(err)
	}

	////////////////////////////////////////////////////////////////////////////
	// Check permissions on pinging and sniffing...
	////////////////////////////////////////////////////////////////////////////
	if os.Geteuid() > 0 && opts.pingCount > 0 {
		logoru.Error("pinging requires root privs")
	}
	if os.Geteuid() > 0 && opts.sniff != "__UNDEFINED__" {
		logoru.Error("Sniffing requires root privs")
	}

	sshHostStr := fmt.Sprintf("%v@%v", config.sshUser, config.sshHost)

	// Sniff the initial ping packets to the sshHost
	ctx, cancelPcap := context.WithCancel(context.Background())
	waitGroup := &sync.WaitGroup{}
	if opts.sniff != "__UNDEFINED__" {
		pcapFilterStr := fmt.Sprintf("host %v", config.sshHost)
		go capturePackets(ctx, waitGroup, opts.sniff, pcapFilterStr)
	}

	// define a UTC time location
	utcTimeZone, err := time.LoadLocation("UTC")
	if err != nil {
		logoru.Error(err)
	}

	// define a local time location
	// locationStr should be something like 'America/Chicago'
	locationTimeZone, err := time.LoadLocation(config.tzLocation)
	if err != nil {
		logoru.Error(err)
	}

	login := time.Now()

	if opts.pingCount > 0 {

		pingTimeStamp := fmt.Sprintf("\n~~~ PING attempt to %v at %v / %v ~~~\n", config.sshHost, login.In(utcTimeZone), login.In(locationTimeZone))
		_, err = logFile.WriteString(pingTimeStamp)
		if err != nil {
			logoru.Error(err)
		}

		/////////////////////////////////////////////////////////////////////////////
		// Build a new Prometheus pro-bing ICMP ping probe and print ping-stats
		// to stdout
		/////////////////////////////////////////////////////////////////////////////
		startPing, err := probing.NewPinger(config.sshHost)
		// Derive ping timeout in seconds from CLI *pingInterval (in milliseconds).
		// This timeout assumes we wait for one more ping timeout than --pingCount
		// specified from the CLI.
		pingTimeoutSeconds := ((time.Duration(opts.pingInterval) * time.Millisecond) * time.Duration(opts.pingCount+1)).Milliseconds() / 1000.0
		startPing.Size = opts.pingSizeBytes
		startPing.Count = opts.pingCount
		startPing.Interval = time.Duration(opts.pingInterval) * time.Millisecond
		startPing.Timeout = time.Duration(pingTimeoutSeconds) * time.Second
		// As of 8-Nov-2023, pinger.MaxRtt is still waiting on a PR review before
		// merge.  See https://github.com/prometheus-community/pro-bing/pull/49
		// startPing.MaxRtt = time.Duration(pingTimeoutSeconds) * time.Second
		startPing.SetPrivileged(true)
		err = startPing.Run() // Blocks until finished.
		if err != nil {
			logoru.Critical(err)
		}

		stats := startPing.Statistics()
		if stats.PacketsRecv == 0 {
			if opts.failOnPingLoss {
				// logoru.Critical() automatically makes the binary die...
				logoru.Critical(fmt.Sprintf("0 of %v ICMP %v byte ping packets received (per-ping timeout: %v milliseconds); failing.", opts.pingCount, opts.pingSizeBytes, opts.pingInterval))

			} else {
				// logoru.Warning() allows the program to continue...
				logoru.Warning(fmt.Sprintf("0 of %v ICMP %v byte ping packets received (per-ping timeout: %v milliseconds); skipping login while host is down.", opts.pingCount, opts.pingSizeBytes, opts.pingInterval))
				return sshLoopSleepSeconds
			}
		}
		// Call printPingStats()
		printPingStats(stats, opts.pingSizeBytes)
	}

	// get an expect console, and debug if called as such...
	console := newExpectConsole(opts.debug, logFile)
	defer console.Close()
	defer logFile.Close()

	// for now, ignore local ~/.ssh/config keyExchangAlgorithms settnigs...
	keyExchangAlgorithms := "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
	keyExchangeArg := fmt.Sprintf("KexAlgorithms=%v", keyExchangAlgorithms)
	keepAliveArg := fmt.Sprintf("ServerAliveInterval=%v", opts.sshKeepalive)
	if opts.debug {
		logoru.Debug(fmt.Sprintf("Calling `ssh -o %v -o %v %v`", keepAliveArg, keyExchangeArg, sshHostStr))
	}
	sshSession := exec.Command("ssh", "-o", keepAliveArg, "-o", keyExchangeArg, sshHostStr)
	sshSession = spawnSshCmd(sshAuthentication, config.sshPassword, fmt.Sprint(opts.sshKeepalive), keyExchangAlgorithms, sshHostStr)

	loginTimeStamp := fmt.Sprintf("\n~~~ LOGIN attempt to %v at %v / %v ~~~\n", sshHostStr, login.In(utcTimeZone), login.In(locationTimeZone))
	_, err = logFile.WriteString(loginTimeStamp)
	if err != nil {
		logoru.Error(err)
	}

	// Assign the console ssh session stdin/stdout/stderr to console TTYs...
	sshSession.Stdin = console.Tty()
	sshSession.Stderr = console.Tty()
	sshSession.Stdout = console.Tty()

	// start the ssh session command...
	err = sshSession.Start()
	if err != nil {
		logoru.Error(err)
	}
	logoru.Info(fmt.Sprintf("Spawned ssh to %v", config.sshHost))

	if sshAuthentication == "none" {
		logoru.Debug("Logging in with no SSH authentication")
	} else if sshAuthentication == "password" {

		////////////////////////////////////////////////////////////////////////////
		// Do NOT explicitly wait for the password prompt here
		// just let the system prompt show up and type it
		// interactively
		////////////////////////////////////////////////////////////////////////////

		// Send a blank line to get a prompt after successful passwd authentication
		_, err = console.SendLine("")
		if err != nil {
			logoru.Error(err)
		}
		_, err = console.Expect(expect.RegexpPattern(sshPromptRegex))
		if err != nil {
			logoru.Error(err)
		}
	} else {
		logoru.Critical(fmt.Sprintf("Unhandled SSH password prompt: %v", sshAuthentication))
	}

	/////////////////////////////////////////////////////////////////////////////
	// erroneousMatch finds `sshPromptRegex`, but it also captures all
	// other multiline input before it.  The following code isolates the
	// match to just the sshPromptRegex
	/////////////////////////////////////////////////////////////////////////////
	erroneousMatch, err := console.Expect(expect.RegexpPattern(sshPromptRegex))
	matchGroupRegex := regexp.MustCompile(fmt.Sprintf("(?P<re_prompt>%v)", sshPromptRegex))
	match := matchGroupRegex.FindStringSubmatch(erroneousMatch)
	namedMatch := make(map[string]string)
	for idx, matchGroup := range matchGroupRegex.SubexpNames() {
		if idx != 0 && matchGroup != "" {
			namedMatch[matchGroup] = match[idx]
		}
	}
	matchPromptStr := namedMatch["re_prompt"]
	/////////////////////////////////////////////////////////////////////////////
	logMsg := fmt.Sprintf("SSH logged into %v, and found a `%v` prompt", config.sshHost, matchPromptStr)
	logoru.Info(logMsg)

	/////////////////////////////////////////////////////////////////////////////
	// send each command in the YAML file to sshHost
	/////////////////////////////////////////////////////////////////////////////
	if sshPrivilegeCmd != "" {
		logoru.Info(sshPrivilegeCmd)
		// Send sshPrivilegeCmd once
		logPrefixConsoleCmd(*console, *logFile, sshSession, opts.verboseTime, config.tzLocation, sshPromptRegex, prefixCmd, sshPrivilegeCmd)
	}
	for idx, _ := range myCommands {
		logoru.Info(myCommands[idx])
		logPrefixConsoleCmd(*console, *logFile, sshSession, opts.verboseTime, config.tzLocation, sshPromptRegex, prefixCmd, myCommands[idx])
	}

	logoru.Success("SSH Session finished")
	defer sshSession.Wait()
	console.Tty().Close()

	logoru.Info("SSH Output done")

	// WriteString() a couple of blank lines
	_, err = logFile.WriteString("\n\n")
	if err != nil {
		logoru.Error(err)
	}

	if opts.sniff != "__UNDEFINED__" {
		// Stop the pcap... gopacket will not stop capturing until one more packet
		// is sent.  We are using Prometheus pro-bing ICMP pings for this purpose.
		defer waitGroup.Wait()
		defer waitGroup.Done()
		cancelPcap()
		pcapFinishPinger, err := probing.NewPinger(config.sshHost)
		pcapFinishPinger.Size = opts.pingSizeBytes
		pcapFinishPinger.Count = 1
		pcapFinishPinger.Interval = time.Duration(opts.pingInterval) * time.Millisecond
		pcapFinishPinger.SetPrivileged(true)
		err = pcapFinishPinger.Run() // Blocks until finished.
		if err != nil {
			logoru.Critical(err)
		}
	}

	return sshLoopSleepSeconds

}

func newExpectConsole(debug bool, logFile *os.File) *expect.Console {
	/////////////////////////////////////////////////////////////////////////////
	// Create a new Netflix go-expect console and return it...
	/////////////////////////////////////////////////////////////////////////////

	if debug {
		// Use this to see all interactive send / expect session...
		console, err := expect.NewConsole(expect.WithStdin(os.Stdin), expect.WithStdout(os.Stdout), expect.WithStdout(logFile))
		if err != nil {
			logoru.Critical(err)
		}
		return console
	} else {
		// Disable all interactive send / expect info to stdout...
		console, err := expect.NewConsole(expect.WithStdout(logFile))
		if err != nil {
			logoru.Critical(err)
		}
		return console
	}
}

func logPrefixConsoleCmd(console expect.Console, logFile os.File, sshSession *exec.Cmd, verboseTime bool, locationStr string, sshPromptRegex string, prefixCmd string, cmd string) {
	////////////////////////////////////////////////////////////////////////////
	//
	// logPrefixConsoleCommand() can be used when you want to run two commands
	// together.  This is useful as a hack around the lack of Cisco's
	// `term exec prompt timestamp` VTY command.
	//
	// The following arguments are accepted:
	//
	// console: a Netflix go-expect instance that logs to logFile
	// logFile: a go file handle from os.OpenFile()
	// sshSession: a bool to enable verbose log file timestamps
	// verboseTime: a bool to enable verbose log file timestamps
	// locationStr: a `time` localization string like 'America/Chicago'
	// sshPromptRegex: 'route-views>' (unpriv Cisco IOS example)
	// prefixCmd: 'show clock' (unpriv Cisco IOS example), if '' dont run a cmd
	// cmd: 'show ip route' (Cisco IOS example)
	//
	// Usage to get verbose timestamp logs of `show ip route 1.1.1.1`:
	//
	// logPairConsoleCommand(console, logFile, true, "America/Chicago", "route-views>", "show clock", "show ip route 1.1.1.1")
	//
	////////////////////////////////////////////////////////////////////////////

	utcTimeZone, err := time.LoadLocation("UTC")
	if err != nil {
		logoru.Error(err)
	}

	// locationStr should be something like 'America/Chicago'
	locationTimeZone, err := time.LoadLocation(locationStr)
	if err != nil {
		logoru.Error(err)
	}

	// run prefixCmd
	console.SendLine(prefixCmd)
	_, err = console.Expect(expect.RegexpPattern(sshPromptRegex))
	if err != nil {
		logoru.Error(err)
	}

	begin := time.Now()
	if verboseTime {
		beginTimeStamp := fmt.Sprintf("\n~~~ CMD BEGIN %v / %v ~~~\n", begin.In(utcTimeZone), begin.In(locationTimeZone))
		_, err = logFile.WriteString(beginTimeStamp)
		if err != nil {
			logoru.Error(err)
		}
	}

	// run empty cmd to get another logged prompt
	console.SendLine("")
	_, err = console.Expect(expect.RegexpPattern(sshPromptRegex))
	if err != nil {
		logoru.Error(err)
	}

	// run cmd
	console.SendLine(cmd)
	if cmd == "exit" || cmd == "quit" || cmd == "logout" {
		// if the last explicit command, wait for the ssh session to finish here...
	} else {
		// run empty cmd to get another logged prompt
		_, err = console.Expect(expect.RegexpPattern(sshPromptRegex))
		if err != nil {
			logoru.Error(err)
		}
		console.SendLine("")
		_, err = console.Expect(expect.RegexpPattern(sshPromptRegex))
		if err != nil {
			logoru.Error(err)
		}
	}

	// capture the commands finish time
	finish := time.Now()

	if verboseTime {
		// subtract begin from finish and WriteString() the elapsed time
		elapsed := fmt.Sprintf("\n~~~   CMD ELAPSED %v ~~~\n", finish.Sub(begin))
		_, err = logFile.WriteString(elapsed)
		if err != nil {
			logoru.Error(err)
		}
	}

	if verboseTime {
		// WriteString() the absolute time
		finishTimeStamp := fmt.Sprintf("~~~   CMD FINISH %v / %v ~~~\n\n", finish.In(utcTimeZone), finish.In(locationTimeZone))
		_, err = logFile.WriteString(finishTimeStamp)
		if err != nil {
			logoru.Error(err)
		}
	}

}

func spawnSshCmd(authentication string, password string, keepalive string, keyalgorithms string, sshHostStr string) *exec.Cmd {
	////////////////////////////////////////////////////////////////////////////
	// Spawn an SSH session based on the type of authentication.  no
	// auhtentication or key authentication requires no password.
	////////////////////////////////////////////////////////////////////////////
	if authentication == "none" {
		sshSession := exec.Command("ssh", sshHostStr)
		return sshSession
	} else if authentication == "password" {
		////////////////////////////////////////////////////////////////////////////
		// Use sshpass to automagically insert the password into the ssh session
		// since it's exceptionally-hard to do so interactively with
		// Netflix go-expect (apparently the ssh password prompt is not sent to the
		// terminal the same way that other ssh interactive text is).  This is
		// different than how Don Libes' Expect handles ssh password prompts (it
		// sees the ssh password without any special sshpass-kludge)
		////////////////////////////////////////////////////////////////////////////
		sshSession := exec.Command("sshpass", "-p", password, "ssh", sshHostStr)
		return sshSession
	} else {
		logoru.Critical(fmt.Sprintf("Authentication %v is not supported", authentication))
	}
	return nil
}

func capturePackets(ctx context.Context, waitGroup *sync.WaitGroup, iface, bpfFilter string) {
	waitGroup.Add(1)
	defer waitGroup.Done()

	for packet := range packets(ctx, waitGroup, iface, bpfFilter) {
		logoru.Debug(packet)
	}
}

func packets(ctx context.Context, waitGroup *sync.WaitGroup, iface, bpfFilter string) chan gopacket.Packet {
	maxMtu := 9000

	fh, err := os.Create("session.pcap")
	if err != nil {
		logoru.Error(err)
	}
	defer fh.Close()

	pcapwriter := pcapgo.NewWriter(fh)
	if err := pcapwriter.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		if err != nil {
			logoru.Critical(err)
		}
	}

	if pcaphandle, err := pcap.OpenLive(iface, int32(maxMtu), false, pcap.BlockForever); err != nil {
		logoru.Critical(err)
	} else if err = pcaphandle.SetBPFFilter(bpfFilter); err != nil {
		logoru.Critical(err)
	} else {
		ps := gopacket.NewPacketSource(pcaphandle, pcaphandle.LinkType())
		for packet := range ps.Packets() {
			if err := pcapwriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				logoru.Critical(err)
			}
		}
		go func() {
			waitGroup.Add(1)
			defer waitGroup.Done()
			<-ctx.Done()
			logoru.Debug("Closing the pcap handle.")
			pcaphandle.Close()
			logoru.Debug("Closed the pcap handle.")
		}()
		return ps.Packets()
	}
	return nil
}

func printPingStats(stats *probing.Statistics, pingSize int) {
	fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
	fmt.Printf("%d %v byte packets transmitted, %d packets received, %v%% packet loss\n",
		stats.PacketsSent, pingSize, stats.PacketsRecv, stats.PacketLoss)
	fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
		stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
}
