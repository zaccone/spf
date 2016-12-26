package main

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Test struct {
	Helo     string
	Host     string
	Mailfrom string
	Result   string
	Receiver string
	Header   string
}

type Tests map[string]Test

type Zonedata map[string][]map[string]string

type TestCase struct {
	Comment  string
	Tests    Tests
	Zonedata Zonedata
}

type TestCases []TestCase

const fname = "./test.yml"

func main() {

	fh, err := ioutil.ReadFile(fname)
	if err != nil {
		panic(err)
	}

	var tc TestCases
	err = yaml.Unmarshal(fh, &tc)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n", tc)

}
