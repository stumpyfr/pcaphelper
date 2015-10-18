package pcaphelper

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"
)

// IsPcap return true if the file is a valid pcap, false if not
func IsPcap(filepath string) (bool, error) {
	data, err := readHeaders(filepath)
	if err != nil {
		return false, err
	}

	return isPcap(data)
}

// GetVersion return the major and minor version of the pcap file
func GetVersion(filepath string) (int, int, error) {
	data, err := readHeaders(filepath)
	if err != nil {
		return -1, -1, err
	}
	isPcap, err := isPcap(data)
	if err != nil {
		return -1, -1, err
	} else if isPcap == false {
		return -1, -1, errors.New("not a valid pcap")
	}

	major := binary.LittleEndian.Uint16(data[4 : 4+2])
	minor := binary.LittleEndian.Uint16(data[6 : 6+2])

	return (int)(major), (int)(minor), nil
}

// GetTimestamp returns the timestamp of the first packet
func GetTimestamp(filepath string) (*time.Time, error) {
	data, err := readHeaders(filepath)
	if err != nil {
		return nil, err
	}
	isPcap, err := isPcap(data)
	if err != nil {
		return nil, err
	} else if isPcap == false {
		return nil, errors.New("not a valid pcap")
	}

	if len(data) < 24+4 {
		return nil, errors.New("no packet the in pcap")
	}

	i := binary.LittleEndian.Uint32(data[24 : 24+4]) // access to ts_sec; in the first packet's heade
	t := time.Unix((int64)(i), 0)
	return &t, nil
}

// GetMD5 returns the md5 hash of the file
func GetMD5(filename string) (string, error) {
	var result []byte
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(result)), nil
}

// GetSHA1 returns the sha1 hash of the file
func GetSHA1(filename string) (string, error) {
	var result []byte
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha1.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(result)), nil
}

func isPcap(data []byte) (bool, error) {
	if len(data) < 24 {
		return false, errors.New("invalid pcap header")
	}
	i := binary.LittleEndian.Uint32(data[0:4])
	if 0xa1b2c3d4 == i {
		return true, nil
	}
	return false, nil
}

func readHeaders(filepath string) ([]byte, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return []byte{}, err
	}
	defer f.Close()

	data := make([]byte, 24+16) //pcap header + first packet header
	_, err = f.Read(data)
	if err != nil {
		return []byte{}, err
	}

	return data, nil
}
