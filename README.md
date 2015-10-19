# pcaphelper

pcaphelper is a small package to get some information about pcap file.

the goals are performance and no dependencies

Currently focus on pcap only (pcap nano is supported for the detection), pcap-ng is not supported

# functions

```
IsPcap(filename string) (PcapType, error)
GetVersion(filename string) (major, minor, error)
GetStartTimestamp(filename string) (*time.Time, error)
GetEndTimestamp(filename string) (*time.Time, error)
GetMD5(filename string) (string, error)
GetSHA1(filename string) (string, error)
GetDataLink(filename string) (DataLink, error)
```

you can find the full documentation here: https://godoc.org/github.com/stumpyfr/pcaphelper

# Roadmap

* [x] GetDataLink
* [x] GetNumberOfPacket
* [x] GetDuration
* [x] GetStartTimestamp
* [x] GetEndTimestamp
