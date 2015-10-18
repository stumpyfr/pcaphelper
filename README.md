# pcaphelper

pcaphelper is a small package to get some information about pcap file.

the goals are performance and no dependencies

Currently focus on pcap only, pcap-ng is not supported

# functions

```
IsPcap(filename string) (bool, error)
GetVersion(filename string) (major, minor, error)
GetTimestamp(filename string) (*time.Time, error)
GetMD5(filename string) (string, error)
GetSHA1(filename string) (string, error)
```

you can find the full documentation here: https://godoc.org/github.com/stumpyfr/pcaphelper

# Roadmap

* [ ] GetEncapsulation
* [ ] GetNumberOfPacket
* [ ] GetDuration
* [ ] GetStarttime
* [ ] GetEndTime
