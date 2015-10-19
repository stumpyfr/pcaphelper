package pcaphelper

import (
	"testing"
	"time"

	pcaphelper "."
)

const VALID_PCAP = "test.pcap"

//const VALID_PCAP = "dhcp-nanosecond.pcap"

func TestIsPcap(t *testing.T) {
	ret, err := pcaphelper.IsPcap(VALID_PCAP)
	if err != nil {
		t.Error(err)
	}
	if ret == pcaphelper.INVALID {
		t.Error("test.pcap is a valid pcap")
	}

	_, err = pcaphelper.IsPcap("toto")
	if err == nil {
		t.Error("file doesn't exist!")
	}

	ret, err = pcaphelper.IsPcap("helper.go")
	if ret != pcaphelper.INVALID && err == nil {
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

func TestGetFirstTimestamp(t *testing.T) {
	ts, err := pcaphelper.GetFirstTimestamp(VALID_PCAP)
	if err != nil {
		t.Error(err)
	}
	if ts.String() != "2009-03-18 23:05:14 +0400 GST" {
		t.Error("incorrect timestamp")
	}
}

func TestGetDuration(t *testing.T) {
	d, err := pcaphelper.GetDuration(VALID_PCAP)
	if err != nil {
		t.Error(err)
	}

	excepted, _ := time.ParseDuration("45s")
	if *d != excepted {
		t.Error("invalid duration")
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
}

func TestNumberOfPacket(t *testing.T) {
	nb, err := pcaphelper.NumberOfPacket(VALID_PCAP)
	if err != nil {
		t.Error(err)
	}
	if nb != 4059 {
		t.Error("invalid number of packet")
	}
}

func TestGetLastTimestamp(t *testing.T) {
	ts, err := pcaphelper.GetLastTimestamp(VALID_PCAP)
	if err != nil {
		t.Error(err)
	}

	if ts.String() != "2009-03-18 23:05:59 +0400 GST" {
		t.Error("incorrect timestamp")
	}
}

func TestDataLink(t *testing.T) {
	dt, err := pcaphelper.GetDataLink(VALID_PCAP)
	if err != nil {
		t.Error(err)
	}

	if dt != pcaphelper.LINKTYPE_ETHERNET {
		t.Error("invalid data link")
	}
}
