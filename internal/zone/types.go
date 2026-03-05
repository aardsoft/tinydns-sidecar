package zone

// ZoneFile mirrors the value under dns_zones.<name> in the Ansible tinydns YAML.
// Pointer fields in RecordSet allow nil-checking for merge semantics.
type ZoneFile struct {
	Servers map[string]*ServerEntry `yaml:"servers,omitempty"`
	Serial  int                     `yaml:"serial,omitempty"`
	Refresh int                     `yaml:"refresh,omitempty"`
	Retry   int                     `yaml:"retry,omitempty"`
	Expire  int                     `yaml:"expire,omitempty"`
	Minimum int                     `yaml:"minimum,omitempty"`
	TTL     int                     `yaml:"ttl,omitempty"`
	Records map[string]RecordSet    `yaml:"records,omitempty"`
}

// ServerEntry represents a nameserver. The API accepts only the map form
// (servers: {ns1.foo.: null}), not the list form.
type ServerEntry struct {
	IP       string   `yaml:"ip,omitempty"`
	IPs      []string `yaml:"ips,omitempty"`
	Location string   `yaml:"location,omitempty"`
}

// RecordSet holds all record types for a single hostname. Pointer fields so
// nil means "not present in upload" — critical for merge semantics and
// KnownFields validation.
type RecordSet struct {
	A       *ARecord            `yaml:"a,omitempty"`
	AAAA    *AAAARecord         `yaml:"aaaa,omitempty"`
	APTR    *APTRRecord         `yaml:"aptr,omitempty"`
	AAAAPtr *AAAAPTRRecord      `yaml:"aaaaptr,omitempty"`
	CNAME   *CNAMERecord        `yaml:"cname,omitempty"`
	MX      *MXRecord           `yaml:"mx,omitempty"`
	SRV     map[string]SRVEntry `yaml:"srv,omitempty"` // key: "_svc._proto"
	TXT     *TXTRecord          `yaml:"txt,omitempty"`
	SPF     *SPFRecord          `yaml:"spf,omitempty"`
}

type ARecord struct {
	IPv4     string   `yaml:"ipv4,omitempty"`
	IPv4s    []string `yaml:"ipv4s,omitempty"`
	Aliases  []string `yaml:"aliases,omitempty"`
	TTL      int      `yaml:"ttl,omitempty"`
	Location string   `yaml:"location,omitempty"`
}

type AAAARecord struct {
	IPv6     string   `yaml:"ipv6,omitempty"`
	Aliases  []string `yaml:"aliases,omitempty"`
	TTL      int      `yaml:"ttl,omitempty"`
	Location string   `yaml:"location,omitempty"`
}

type APTRRecord struct {
	IPv4    string   `yaml:"ipv4,omitempty"`
	IPv4s   []string `yaml:"ipv4s,omitempty"`
	Aliases []string `yaml:"aliases,omitempty"`
	TTL     int      `yaml:"ttl,omitempty"`
}

type AAAAPTRRecord struct {
	IPv6    string   `yaml:"ipv6,omitempty"`
	Aliases []string `yaml:"aliases,omitempty"`
	TTL     int      `yaml:"ttl,omitempty"`
}

type CNAMERecord struct {
	PTR string `yaml:"ptr"`
}

type MXRecord struct {
	Priority int `yaml:"priority"`
	TTL      int `yaml:"ttl,omitempty"`
}

type SRVEntry struct {
	Port     int    `yaml:"port"`
	Weight   int    `yaml:"weight,omitempty"`
	Priority int    `yaml:"priority,omitempty"`
	IPv4     string `yaml:"ipv4,omitempty"`
	TTL      int    `yaml:"ttl,omitempty"`
}

type TXTRecord struct {
	Data []string `yaml:"data"`
}

type SPFRecord struct {
	Data []string `yaml:"data"`
}
