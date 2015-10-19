package pcaphelper

// PcapType represents the different type of pcap file based on the magic code
type PcapType int

// DataLink represents the data link of the pcap
type DataLink int

const (
	INVALID PcapType = 0
	PCAP             = 0xa1b2c3d4
	PCAP_NS          = 0xa1b23c4d

	LINKTYPE_NULL                DataLink = 0
	LINKTYPE_ETHERNET                     = 1
	LINKTYPE_IEEE802_5                    = 6
	LINKTYPE_IEEE802_11                   = 105
	LINKTYPE_IEEE802_11_RADIOTAP          = 217
	LINKTYPE_BLUETOOTH_LE_LL              = 251
)
