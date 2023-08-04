package main

import (
	"log"
	"net"
	"os"
	_ "embed"

	"github.com/oschwald/geoip2-golang"
)

//go:embed "dir/GeoIP2-ISP.mmdb"
var geoipDB []byte

func GetMMDB() (*geoip2.Reader, error) {
	var db *geoip2.Reader
	var err error

	_, err = os.Stat("/usr/share/GeoIP/GeoIP2-ISP.mmdb")
	if err == nil {
		db, err = geoip2.Open("/usr/share/GeoIP/GeoIP2-ISP.mmdb")
		if err != nil {
			return nil, err
		}
		defer db.Close()
	} else {
		log.Printf("/usr/share/GeoIP/GeoIP2-ISP.mmdb not found, using potentially outdated ASN DB\n\n")
		db, err = geoip2.FromBytes(geoipDB)
		if err != nil {
			return nil, err
		}
		defer db.Close()
	}
	return db, nil //nil error
}

func QueryMaxMind(IP string, DB *geoip2.Reader) (int, error) {

	ip := net.ParseIP(IP)
	record, err := DB.ASN(ip)
	if err != nil {
		return 0, err
	}
	return int(record.AutonomousSystemNumber), nil
}
