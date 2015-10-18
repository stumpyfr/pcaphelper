package pcaphelper

// based on http://www.tcpdump.org/linktypes.html
var (
	datalinks = map[uint32]string{
		0:   "LINKTYPE_NULL",
		1:   "LINKTYPE_ETHERNET",
		6:   "LINKTYPE_IEEE802_5",
		105: "LINKTYPE_IEEE802_11",
		127: "LINKTYPE_IEEE802_11_RADIOTAP",
		251: "LINKTYPE_BLUETOOTH_LE_LL",
	}
)
