package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"strconv"
	"github.com/go-gota/gota/dataframe"
	"github.com/oschwald/geoip2-golang"

)

type Row struct {
	LocalIP       string
	LocalPort     int
	RemoteIP      string
	RemotePort    int
	RemoteASN     int
	MSS           int
	PMTU          int
	RCVMSS        int
	ADVMSS        int
	BytesSent     int
	BytesReceived int
}

func parseRow(row string, DB *geoip2.Reader) (Row, error) {
	var r Row
	pairs := strings.Split(row, " ")

	for _, pair := range pairs {
		kv := strings.Split(pair, "=")
		if len(kv) != 2 { return r, fmt.Errorf("invalid key-value pair: %s", pair) }
		key   := kv[0]
		value := kv[1]

		switch key {
		case "local_ip":
			r.LocalIP          = value
	        case "local_port":
	        	r.LocalPort, _     = strconv.Atoi(value)
	        case "remote_ip":
	        	r.RemoteIP         = value
			r.RemoteASN, _     = QueryMaxMind(value, DB)
	        case "remote_port":
	        	r.RemotePort, _    = strconv.Atoi(value)
	        case "mss":
	        	r.MSS, _           = strconv.Atoi(value)
	        case "pmtu":
	        	r.PMTU, _          = strconv.Atoi(value)
	        case "rcvmss":
	        	r.RCVMSS, _        = strconv.Atoi(value)
	        case "advmss":
	        	r.ADVMSS, _        = strconv.Atoi(value)
	        case "bytes_sent":
	        	r.BytesSent, _     = strconv.Atoi(value)
	        case "bytes_received":
	        	r.BytesReceived, _ = strconv.Atoi(value)
	        default:
	        	return r, fmt.Errorf("unknown key: %s", key)
	        }
	}
	return r, nil
}

func main() {

	FormattedSsOutput := Ssfmt()
	var rows []Row
	DB, _ := GetMMDB()
	scanner := bufio.NewScanner(strings.NewReader(FormattedSsOutput))
	for scanner.Scan() {
		line := scanner.Text()
		rowStruct, err := parseRow(line, DB); if err != nil { log.Fatal(err) }
		rows = append(rows, rowStruct)
	}

	df := dataframe.LoadStructs(rows)

	if len(os.Args) > 1 {
		groupColumn := os.Args[3]
		groups := df.GroupBy(groupColumn)
		groupmap := groups.GetGroups()
		for key, df := range groupmap {
			fmt.Println(key)
			fmt.Println(df)
		}
	} else { fmt.Println(df) }

	fmt.Println("               ",df.Names())


	//dataCSV, err := os.Create("data.csv"); if err != nil { log.Fatal(err) }; defer dataCSV.Close()
	//if err := df.WriteCSV(dataCSV); err != nil { log.Fatal(err) }

	if err := scanner.Err(); err != nil { log.Fatal(err) }

}

