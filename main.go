package main

import (
        "os"
        "os/exec"

        expect "github.com/Netflix/go-expect"
        "github.com/gleich/logoru"
)

func main() {

        logFile, err := os.OpenFile("command.log", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
        if err != nil {
                logoru.Critical(err)
        }

        //console, err := expect.NewConsole(expect.WithStdin(os.Stdin), expect.WithStdout(os.Stdout), expect.WithStdout(logFile))
        console, err := expect.NewConsole(expect.WithStdout(logFile))
        if err != nil {
                logoru.Critical(err)
        }
        defer logFile.Close()
        defer console.Close()

        sshSession := exec.Command("ssh", "rviews@route-views.routeviews.org")
        // Assign the console ssh session stdin/stdout/stderr to console TTYs...
        sshSession.Stdin = console.Tty()
        sshSession.Stdout = console.Tty()
        sshSession.Stderr = console.Tty()

        // start the ssh session command...
        err = sshSession.Start()
        if err != nil {
                logoru.Error(err)
        }
        logoru.Info("Spawned ssh")

        _, err = console.ExpectString("route-views>")
        if err != nil {
                logoru.Error(err)
        }
        logoru.Info("Found route-views prompt")

        console.SendLine("term len 0")

        _, err = console.ExpectString("route-views>")
        if err != nil {
                logoru.Error(err)
        }
        logoru.Info("Found another route-views prompt")

        logoru.Info("Sending bgp command")
        console.SendLine("show ip bgp 1.1.1.1 best")
        _, err = console.ExpectString("route-views>")
        if err != nil {
                logoru.Error(err)
        }
        logoru.Info("Completed bgp command")

        // exit the console and wait for the ssh session to finish...
        console.SendLine("exit")
        err = sshSession.Wait()
        if err != nil {
                logoru.Error(err)
        }

        console.Tty().Close()
        matchString, err := console.Expect(expect.RegexpPattern(`Connection to \S+ closed.`))
        if err != nil {
                logoru.Error(err)
        }
        logoru.Debug(matchString)

}
