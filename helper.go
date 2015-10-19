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

// IsPcap returns the PcapType based on the magic code of the file
func IsPcap(filepath string) (PcapType, Endianness, error) {
	data, err := readHeaders(filepath)
	if err != nil {
		return INVALID, LITTLE, err
	}

	return isPcap(data)
}

// GetDataLink returns the datalink of the pcap
func GetDataLink(filepath string) (DataLink, error) {
	data, err := readHeaders(filepath)
	if err != nil {
		return LINKTYPE_NULL, err
	}

	typ, e, err := isPcap(data)
	if err != nil {
		return LINKTYPE_NULL, err
	} else if typ == INVALID || typ == PCAP_NG {
		return LINKTYPE_NULL, errors.New("invalid pcap")
	}

	var dt uint32
	if e == LITTLE {
		dt = binary.LittleEndian.Uint32(data[20 : 20+4])
	} else {
		dt = binary.BigEndian.Uint32(data[20 : 20+4])
	}

	return (DataLink)(dt), nil
}

// GetVersion return the major and minor version of the pcap file
func GetVersion(filepath string) (int, int, error) {
	data, err := readHeaders(filepath)
	if err != nil {
		return -1, -1, err
	}
	typ, e, err := isPcap(data)
	if err != nil {
		return -1, -1, err
	} else if typ == INVALID || typ == PCAP_NG {
		return -1, -1, errors.New("not a valid pcap")
	}

	if e == LITTLE {
		major := binary.LittleEndian.Uint16(data[4 : 4+2])
		minor := binary.LittleEndian.Uint16(data[6 : 6+2])
		return (int)(major), (int)(minor), nil
	} else {
		major := binary.BigEndian.Uint16(data[4 : 4+2])
		minor := binary.BigEndian.Uint16(data[6 : 6+2])
		return (int)(major), (int)(minor), nil
	}
}

// GetFirstTimestamp returns the timestamp of the first packet
func GetFirstTimestamp(filepath string) (*time.Time, error) {
	data, err := readHeaders(filepath)
	if err != nil {
		return nil, err
	}
	typ, e, err := isPcap(data)
	if err != nil {
		return nil, err
	} else if typ == INVALID || typ == PCAP_NG {
		return nil, errors.New("not a valid pcap")
	}

	if len(data) < 24+4 {
		return nil, errors.New("no packet the in pcap")
	}

	if e == LITTLE {
		i := binary.LittleEndian.Uint32(data[24 : 24+4]) // access to ts_sec; in the first packet's heade
		t := time.Unix((int64)(i), 0)
		return &t, nil
	} else {
		i := binary.BigEndian.Uint32(data[24 : 24+4]) // access to ts_sec; in the first packet's heade
		t := time.Unix((int64)(i), 0)
		return &t, nil
	}
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

// NumberOfPacket returns the number of packet in the pcap
func NumberOfPacket(filename string) (int, error) {
	counter := 0

	f, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	data := make([]byte, 24) //pcap header
	_, err = f.Read(data)
	if err != nil {
		return 0, err
	}
	typ, e, err := isPcap(data)
	if err != nil {
		return 0, err
	} else if typ == INVALID || typ == PCAP_NG {
		return 0, errors.New("invalid pcap")
	}

	for {
		// iterate over packet header, seek over packet
		data = make([]byte, 16)
		_, err = f.Read(data)
		if err != nil {
			if err == io.EOF {
				return counter, nil
			}
			return 0, err
		}

		var i uint32
		if e == LITTLE {
			i = binary.LittleEndian.Uint32(data[8 : 8+4]) // access incl_len
		} else {
			i = binary.BigEndian.Uint32(data[8 : 8+4]) // access incl_len
		}
		f.Seek((int64)(i), os.SEEK_CUR)

		counter++
	}
	return 0, nil
}

// GetLastTimestamp returns the timestamp of the last packet
func GetLastTimestamp(filename string) (*time.Time, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data := make([]byte, 24) //pcap header
	_, err = f.Read(data)
	if err != nil {
		return nil, err
	}
	typ, e, err := isPcap(data)
	if err != nil {
		return nil, err
	} else if typ == INVALID || typ == PCAP_NG {
		return nil, errors.New("invalid pcap")
	}

	var t time.Time
	for {
		// iterate over packet header, seek over packet
		data = make([]byte, 16)
		_, err = f.Read(data)
		if err != nil {
			if err == io.EOF {
				return &t, nil
			}
			return nil, err
		}

		var i uint32
		if e == LITTLE {
			i = binary.LittleEndian.Uint32(data[0:4]) // access to ts_sec
			t = time.Unix((int64)(i), 0)
			i = binary.LittleEndian.Uint32(data[8 : 8+4]) // access incl_len
		} else {
			i = binary.BigEndian.Uint32(data[0:4]) // access to ts_sec
			t = time.Unix((int64)(i), 0)
			i = binary.BigEndian.Uint32(data[8 : 8+4]) // access incl_len
		}

		f.Seek((int64)(i), os.SEEK_CUR)
	}
	return nil, nil
}

func GetDuration(filename string) (*time.Duration, error) {
	start, err := GetFirstTimestamp(filename)
	if err != nil {
		return nil, err
	}
	end, err := GetLastTimestamp(filename)
	if err != nil {
		return nil, err
	}
	delta := end.Sub(*start)
	return &delta, nil
}

func isPcap(data []byte) (PcapType, Endianness, error) {
	if len(data) < 24 {
		return INVALID, LITTLE, errors.New("invalid pcap header")
	}
	i := binary.LittleEndian.Uint32(data[0:4])
	if i == PCAP {
		return PCAP, LITTLE, nil
	} else if i == PCAP_SWAPPED {
		return PCAP, BIG, nil
	} else if i == PCAP_NS {
		return PCAP_NS, LITTLE, nil
	} else if i == PCAP_NS_SWAPPED {
		return PCAP_NS, BIG, nil
	} else if i == PCAP_NG {
		return PCAP_NG, LITTLE, nil
	}
	return INVALID, LITTLE, nil
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
