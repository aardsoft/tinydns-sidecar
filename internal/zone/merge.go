package zone

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Merge applies incoming on top of existing using PATCH semantics:
// add/update records, never delete records absent from incoming.
//
// SOA fields: incoming non-zero wins; serial only advances (never regresses).
// Servers/Records: upsert — adds new keys, overwrites matching keys, keeps unmentioned keys.
// RecordSet granularity: record-type level (non-nil A field fully replaces existing A).
// SRV map: upsert at service-key level.
//
// Deep copy is done via marshal-to-YAML-and-back to avoid aliasing bugs.
func Merge(existing, incoming ZoneFile) (ZoneFile, error) {
	// Deep-copy existing as the base.
	base, err := deepCopy(existing)
	if err != nil {
		return ZoneFile{}, fmt.Errorf("deep copy existing: %w", err)
	}

	// SOA integer fields: incoming non-zero wins.
	if incoming.Refresh != 0 {
		base.Refresh = incoming.Refresh
	}
	if incoming.Retry != 0 {
		base.Retry = incoming.Retry
	}
	if incoming.Expire != 0 {
		base.Expire = incoming.Expire
	}
	if incoming.Minimum != 0 {
		base.Minimum = incoming.Minimum
	}
	if incoming.TTL != 0 {
		base.TTL = incoming.TTL
	}
	// Serial only advances.
	if incoming.Serial != 0 && incoming.Serial >= base.Serial {
		base.Serial = incoming.Serial
	}

	// Servers: upsert.
	if base.Servers == nil && len(incoming.Servers) > 0 {
		base.Servers = make(map[string]*ServerEntry)
	}
	for k, v := range incoming.Servers {
		base.Servers[k] = v
	}

	// Records: upsert per hostname, then merge record-type fields.
	if base.Records == nil && len(incoming.Records) > 0 {
		base.Records = make(map[string]RecordSet)
	}
	for host, inRS := range incoming.Records {
		if existRS, ok := base.Records[host]; ok {
			base.Records[host] = mergeRecordSet(existRS, inRS)
		} else {
			base.Records[host] = inRS
		}
	}

	return base, nil
}

// mergeRecordSet merges at record-type granularity: a non-nil field in incoming
// fully replaces the corresponding field in existing.
func mergeRecordSet(existing, incoming RecordSet) RecordSet {
	result := existing
	if incoming.A != nil {
		result.A = incoming.A
	}
	if incoming.AAAA != nil {
		result.AAAA = incoming.AAAA
	}
	if incoming.APTR != nil {
		result.APTR = incoming.APTR
	}
	if incoming.AAAAPtr != nil {
		result.AAAAPtr = incoming.AAAAPtr
	}
	if incoming.CNAME != nil {
		result.CNAME = incoming.CNAME
	}
	if incoming.MX != nil {
		result.MX = incoming.MX
	}
	if incoming.TXT != nil {
		result.TXT = incoming.TXT
	}
	if incoming.SPF != nil {
		result.SPF = incoming.SPF
	}
	// SRV: upsert at service-key level.
	if len(incoming.SRV) > 0 {
		if result.SRV == nil {
			result.SRV = make(map[string]SRVEntry)
		}
		for k, v := range incoming.SRV {
			result.SRV[k] = v
		}
	}
	return result
}

func deepCopy(z ZoneFile) (ZoneFile, error) {
	data, err := yaml.Marshal(z)
	if err != nil {
		return ZoneFile{}, err
	}
	var out ZoneFile
	if err := yaml.Unmarshal(data, &out); err != nil {
		return ZoneFile{}, err
	}
	return out, nil
}
