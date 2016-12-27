package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

type Zonedata map[string][]map[string]string

type Test struct {
	Helo     string
	Host     string
	Mailfrom string
	Result   string
	Receiver string
	Header   string
}

type Tests map[string]Test

type TestCase struct {
	Comment  string
	Tests    Tests
	Zonedata Zonedata
}

type JSONTest []TestCase

func main() {
	const fname = "/tmp/asd.json"
	fh, err := ioutil.ReadFile(fname)
	if err != nil {
		panic(err)
	}

	var tc JSONTest
	err = json.Unmarshal(fh, &tc)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n", tc)

	for _, test := range tc {
		fmt.Printf("val: %+v\n", test)
	}

}
