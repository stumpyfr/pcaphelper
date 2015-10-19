package pcaphelper

// PcapType represents the different type of pcap file based on the magic code
type PcapType int

// DataLink represents the data link of the pcap
type DataLink int

// Endianness represents the endian type of the pcap
type Endianness int

const (
	LITTLE Endianness = 0
	BIG               = 1

	INVALID         PcapType = 0
	PCAP                     = 0xa1b2c3d4
	PCAP_SWAPPED             = 0xd4c3b2a1
	PCAP_NS                  = 0xa1b23c4d
	PCAP_NS_SWAPPED          = 0x4d3cb2a1
	PCAP_NG                  = 0x0a0d0d0a

	LINKTYPE_NULL                DataLink = 0
	LINKTYPE_ETHERNET                     = 1
	LINKTYPE_IEEE802_5                    = 6
	LINKTYPE_IEEE802_11                   = 105
	LINKTYPE_IEEE802_11_RADIOTAP          = 217
	LINKTYPE_BLUETOOTH_LE_LL              = 251
)
