package main

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

func Ssfmt() (output string) {

	cmd := exec.Command("ss", "-4HtinoO")
	stdout, err := cmd.StdoutPipe(); if err != nil { fmt.Println(err); return }

	err = cmd.Start(); if err != nil { fmt.Println(err); return }

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Fields(line)
		if len(fields) < 5 { continue }

		local := strings.Split(fields[3], ":")
		remote := strings.Split(fields[4], ":")

		selectedColumns := fmt.Sprintf("local_ip=%s local_port=%s remote_ip=%s remote_port=%s ", local[0], local[1], remote[0], remote[1])

		mssRegexp := regexp.MustCompile(`mss[:=](\S+)`)
		pmtuRegexp := regexp.MustCompile(`pmtu[:=](\S+)`)
		bytesReceivedRegexp := regexp.MustCompile(`bytes_received[:=](\S+)`)
		bytesSentRegexp := regexp.MustCompile(`bytes_sent[:=](\S+)`)

		for _, field := range fields {
			if mss := mssRegexp.FindStringSubmatch(field); mss != nil {
				selectedColumns += fmt.Sprintf("mss=%s ", mss[1])
			} else if pmtu := pmtuRegexp.FindStringSubmatch(field); pmtu != nil {
				selectedColumns += fmt.Sprintf("pmtu=%s ", pmtu[1])
			} else if bytesReceived := bytesReceivedRegexp.FindStringSubmatch(field); bytesReceived != nil {
				selectedColumns += fmt.Sprintf("bytes_received=%s ", bytesReceived[1])
			} else if bytesSent := bytesSentRegexp.FindStringSubmatch(field); bytesSent != nil {
				selectedColumns += fmt.Sprintf("bytes_sent=%s ", bytesSent[1])
			}
		}

		selectedColumns = strings.TrimRight(selectedColumns, " ")
		output += (selectedColumns + "\n")
	}
	err = cmd.Wait(); if err != nil {	fmt.Println(err) }

	return output
}

