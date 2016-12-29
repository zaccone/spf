package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type Zonedata map[string][]map[string]string

type Test struct {
	Helo        string
	Host        string
	Mailfrom    string
	Result      string
	Receiver    string
	Header      string
	Comment     string `json:",omitempty"`
	Explanation string `json:",omitempty"`
}

type Tests map[string]Test

type TestCase struct {
	Comment  string
	Tests    Tests
	Zonedata Zonedata
}

type JSONTest []TestCase

func runDNS(zone *Zonedata) error {
	fmt.Printf("Running DNS Server for Zone %+v\n", *zone)
	for host, records := range *zone {
		for _, record := range records {
			for t, v := range record {
				fmt.Printf("%s 0 IN %s %s\n", host, t, v)
			}
		}
	}
	return nil
}

func runTests(tc *JSONTest) {
	for _, testcase := range *tc {
		runDNS(&testcase.Zonedata)

		for k, v := range testcase.Tests {
			fmt.Printf("Running test %s spf.CheckHost(ip=%s, domain=%s, sender=%s)\n", k, v.Host, v.Helo, v.Mailfrom)

		}
	}
}

func main() {

	if len(os.Args) < 2 {
		fmt.Printf("Usage %s <file.json>", os.Args[0])
		os.Exit(1)
	}
	fname := os.Args[1]

	fh, err := ioutil.ReadFile(fname)
	if err != nil {
		panic(err)
	}

	var tc JSONTest
	err = json.Unmarshal(fh, &tc)
	if err != nil {
		panic(err)
	}

	runTests(&tc)

}
