package pcaphelper

import (
	"fmt"
	"testing"

	pcaphelper "."
)

const VALID_PCAP = "test.pcap"

func TestIsPcap(t *testing.T) {
	ret, err := pcaphelper.IsPcap(VALID_PCAP)
	if err != nil {
		t.Error(err)
	}
	if ret == false {
		t.Error("test.pcap is a valid pcap")
	}

	_, err = pcaphelper.IsPcap("toto")
	if err == nil {
		t.Error("file doesn't exist!")
	}

	ret, err = pcaphelper.IsPcap("helper.go")
	if ret == true && err == nil {
		t.Error("file is not a valid pcap")
	}
}

func TestGetVersion(t *testing.T) {
	major, minor, err := pcaphelper.GetVersion(VALID_PCAP)
	if err != nil {
		t.Error(err)
	} else if major == -1 || minor == -1 {
		t.Error("invalid version")
	}

	_, _, err = pcaphelper.GetVersion("helper.go")
	if err == nil {
		t.Error("helper.go is not a pcap")
	}
}

func TestGetTimestamp(t *testing.T) {
	ts, err := pcaphelper.GetTimestamp(VALID_PCAP)
	if err != nil {
		t.Error(err)
	}
	if ts.String() != "2009-03-18 23:05:14 +0400 GST" {
		t.Error("incorrect timestamp")
	}
}

func TestGetMD5(t *testing.T) {
	md5, err := pcaphelper.GetMD5(VALID_PCAP)
	if err != nil {
		t.Error(err)
	}

	if md5 != "c420175ce91a7fae11aa4426ad6cbc9d" {
		t.Error("invalid md5")
	}
}

func TestGetSHA1(t *testing.T) {
	sha1, err := pcaphelper.GetSHA1(VALID_PCAP)
	if err != nil {
		t.Error(err)
	}

	if sha1 != "59ad636d4dc74684454bc2f7df6ec74efa7a0851" {
		t.Error("invalid md5")
	}

	fmt.Println(sha1)
}
