package zone

import (
	"strings"
	"testing"
)

// --- Validate tests ---

func TestValidate_EmptyZone(t *testing.T) {
	// An empty zone is valid (all fields optional).
	errs := Validate(ZoneFile{})
	if errs != nil {
		t.Errorf("unexpected errors for empty zone: %v", errs)
	}
}

func TestValidate_ValidARecord(t *testing.T) {
	zf := ZoneFile{
		Records: map[string]RecordSet{
			"www.example.com.": {
				A: &ARecord{IPv4: "1.2.3.4"},
			},
		},
	}
	if errs := Validate(zf); errs != nil {
		t.Errorf("unexpected errors: %v", errs)
	}
}

func TestValidate_InvalidIPv4(t *testing.T) {
	zf := ZoneFile{
		Records: map[string]RecordSet{
			"www.example.com.": {
				A: &ARecord{IPv4: "not-an-ip"},
			},
		},
	}
	errs := Validate(zf)
	if errs == nil {
		t.Fatal("expected validation error for invalid IPv4")
	}
	if !strings.Contains(errs.Error(), "ipv4") {
		t.Errorf("expected ipv4 error, got: %v", errs)
	}
}

func TestValidate_ARecordNeitherIPv4NorIPv4s(t *testing.T) {
	zf := ZoneFile{
		Records: map[string]RecordSet{
			"www.example.com.": {
				A: &ARecord{TTL: 300},
			},
		},
	}
	errs := Validate(zf)
	if errs == nil {
		t.Fatal("expected error: A record needs at least one of ipv4/ipv4s")
	}
}

func TestValidate_ValidAAAARecord(t *testing.T) {
	zf := ZoneFile{
		Records: map[string]RecordSet{
			"www.example.com.": {
				AAAA: &AAAARecord{IPv6: "2001:db8::1"},
			},
		},
	}
	if errs := Validate(zf); errs != nil {
		t.Errorf("unexpected errors: %v", errs)
	}
}

func TestValidate_IPv6AsIPv4Rejected(t *testing.T) {
	zf := ZoneFile{
		Records: map[string]RecordSet{
			"host.example.com.": {
				A: &ARecord{IPv4: "2001:db8::1"}, // IPv6 in IPv4 field
			},
		},
	}
	errs := Validate(zf)
	if errs == nil {
		t.Fatal("expected error: IPv6 address in A record IPv4 field")
	}
}

func TestValidate_CNAMEEmptyPTR(t *testing.T) {
	zf := ZoneFile{
		Records: map[string]RecordSet{
			"alias.example.com.": {
				CNAME: &CNAMERecord{PTR: ""},
			},
		},
	}
	errs := Validate(zf)
	if errs == nil {
		t.Fatal("expected error: CNAME with empty PTR")
	}
}

func TestValidate_MXPriorityRange(t *testing.T) {
	cases := []struct {
		priority int
		valid    bool
	}{
		{0, true},
		{10, true},
		{65535, true},
		{-1, false},
		{65536, false},
	}
	for _, tc := range cases {
		zf := ZoneFile{
			Records: map[string]RecordSet{
				"example.com.": {
					MX: &MXRecord{Priority: tc.priority},
				},
			},
		}
		errs := Validate(zf)
		if tc.valid && errs != nil {
			t.Errorf("priority %d: unexpected error: %v", tc.priority, errs)
		}
		if !tc.valid && errs == nil {
			t.Errorf("priority %d: expected error", tc.priority)
		}
	}
}

func TestValidate_SRVPortRange(t *testing.T) {
	cases := []struct {
		port  int
		valid bool
	}{
		{1, true},
		{80, true},
		{65535, true},
		{0, false},
		{65536, false},
	}
	for _, tc := range cases {
		zf := ZoneFile{
			Records: map[string]RecordSet{
				"example.com.": {
					SRV: map[string]SRVEntry{
						"_http._tcp": {Port: tc.port},
					},
				},
			},
		}
		errs := Validate(zf)
		if tc.valid && errs != nil {
			t.Errorf("port %d: unexpected error: %v", tc.port, errs)
		}
		if !tc.valid && errs == nil {
			t.Errorf("port %d: expected error", tc.port)
		}
	}
}

func TestValidate_TXTEmptyData(t *testing.T) {
	zf := ZoneFile{
		Records: map[string]RecordSet{
			"example.com.": {
				TXT: &TXTRecord{Data: []string{}},
			},
		},
	}
	errs := Validate(zf)
	if errs == nil {
		t.Fatal("expected error: TXT with empty data slice")
	}
}

func TestValidate_TXTEmptyElement(t *testing.T) {
	zf := ZoneFile{
		Records: map[string]RecordSet{
			"example.com.": {
				TXT: &TXTRecord{Data: []string{"valid", ""}},
			},
		},
	}
	errs := Validate(zf)
	if errs == nil {
		t.Fatal("expected error: TXT with empty data element")
	}
}

func TestValidate_ServerBadIP(t *testing.T) {
	zf := ZoneFile{
		Servers: map[string]*ServerEntry{
			"ns1.example.com.": {IP: "not-an-ip"},
		},
	}
	errs := Validate(zf)
	if errs == nil {
		t.Fatal("expected error for server with invalid IP")
	}
}

func TestValidate_ServerIPv6InIPField(t *testing.T) {
	zf := ZoneFile{
		Servers: map[string]*ServerEntry{
			"ns1.example.com.": {IP: "2001:db8::1"}, // must be IPv4
		},
	}
	errs := Validate(zf)
	if errs == nil {
		t.Fatal("expected error: server ip must be IPv4")
	}
}

func TestValidate_CollectsMultipleErrors(t *testing.T) {
	zf := ZoneFile{
		Records: map[string]RecordSet{
			"a.example.com.": {A: &ARecord{IPv4: "bad-ip"}},
			"b.example.com.": {AAAA: &AAAARecord{IPv6: "also-bad"}},
		},
	}
	errs := Validate(zf)
	if len(errs) < 2 {
		t.Errorf("expected ≥2 errors, got %d: %v", len(errs), errs)
	}
}

// --- Merge tests ---

func TestMerge_SOAFieldsIncomingNonZeroWins(t *testing.T) {
	existing := ZoneFile{Serial: 10, Refresh: 3600, TTL: 300}
	incoming := ZoneFile{Refresh: 7200, TTL: 600}

	merged, err := Merge(existing, incoming)
	if err != nil {
		t.Fatalf("merge error: %v", err)
	}
	if merged.Refresh != 7200 {
		t.Errorf("Refresh = %d, want 7200", merged.Refresh)
	}
	if merged.TTL != 600 {
		t.Errorf("TTL = %d, want 600", merged.TTL)
	}
	// Serial not in incoming (zero) — should keep existing.
	if merged.Serial != 10 {
		t.Errorf("Serial = %d, want 10 (existing)", merged.Serial)
	}
}

func TestMerge_SerialAdvancesOnly(t *testing.T) {
	existing := ZoneFile{Serial: 100}

	// Lower serial should be ignored.
	merged, err := Merge(existing, ZoneFile{Serial: 50})
	if err != nil {
		t.Fatalf("merge error: %v", err)
	}
	if merged.Serial != 100 {
		t.Errorf("Serial regressed to %d, want 100", merged.Serial)
	}

	// Equal serial is fine.
	merged, err = Merge(existing, ZoneFile{Serial: 100})
	if err != nil {
		t.Fatalf("merge error: %v", err)
	}
	if merged.Serial != 100 {
		t.Errorf("Serial = %d, want 100", merged.Serial)
	}

	// Higher serial advances.
	merged, err = Merge(existing, ZoneFile{Serial: 200})
	if err != nil {
		t.Fatalf("merge error: %v", err)
	}
	if merged.Serial != 200 {
		t.Errorf("Serial = %d, want 200", merged.Serial)
	}
}

func TestMerge_ServersUpsert(t *testing.T) {
	existing := ZoneFile{
		Servers: map[string]*ServerEntry{
			"ns1.example.com.": {IP: "1.2.3.4"},
			"ns2.example.com.": {IP: "5.6.7.8"},
		},
	}
	incoming := ZoneFile{
		Servers: map[string]*ServerEntry{
			"ns2.example.com.": {IP: "9.9.9.9"}, // update
			"ns3.example.com.": {IP: "10.0.0.1"}, // new
		},
	}
	merged, err := Merge(existing, incoming)
	if err != nil {
		t.Fatalf("merge error: %v", err)
	}
	if merged.Servers["ns1.example.com."].IP != "1.2.3.4" {
		t.Error("ns1 should be preserved")
	}
	if merged.Servers["ns2.example.com."].IP != "9.9.9.9" {
		t.Error("ns2 should be updated")
	}
	if merged.Servers["ns3.example.com."].IP != "10.0.0.1" {
		t.Error("ns3 should be added")
	}
}

func TestMerge_RecordsUpsert(t *testing.T) {
	existing := ZoneFile{
		Records: map[string]RecordSet{
			"www.example.com.": {A: &ARecord{IPv4: "1.2.3.4"}},
			"mail.example.com.": {MX: &MXRecord{Priority: 10}},
		},
	}
	incoming := ZoneFile{
		Records: map[string]RecordSet{
			"www.example.com.": {A: &ARecord{IPv4: "9.9.9.9"}}, // update A
			"ftp.example.com.":  {A: &ARecord{IPv4: "2.2.2.2"}}, // new host
		},
	}
	merged, err := Merge(existing, incoming)
	if err != nil {
		t.Fatalf("merge error: %v", err)
	}
	if merged.Records["www.example.com."].A.IPv4 != "9.9.9.9" {
		t.Error("www A should be updated to 9.9.9.9")
	}
	if merged.Records["mail.example.com."].MX.Priority != 10 {
		t.Error("mail MX should be preserved")
	}
	if merged.Records["ftp.example.com."].A.IPv4 != "2.2.2.2" {
		t.Error("ftp should be added")
	}
}

func TestMerge_RecordSetGranularity(t *testing.T) {
	// Incoming has A but no AAAA — existing AAAA should survive.
	existing := ZoneFile{
		Records: map[string]RecordSet{
			"host.example.com.": {
				A:    &ARecord{IPv4: "1.2.3.4"},
				AAAA: &AAAARecord{IPv6: "2001:db8::1"},
			},
		},
	}
	incoming := ZoneFile{
		Records: map[string]RecordSet{
			"host.example.com.": {
				A: &ARecord{IPv4: "9.9.9.9"}, // only updating A
			},
		},
	}
	merged, err := Merge(existing, incoming)
	if err != nil {
		t.Fatalf("merge error: %v", err)
	}
	rs := merged.Records["host.example.com."]
	if rs.A.IPv4 != "9.9.9.9" {
		t.Errorf("A should be 9.9.9.9, got %s", rs.A.IPv4)
	}
	if rs.AAAA == nil || rs.AAAA.IPv6 != "2001:db8::1" {
		t.Error("AAAA should be preserved")
	}
}

func TestMerge_SRVUpsert(t *testing.T) {
	existing := ZoneFile{
		Records: map[string]RecordSet{
			"example.com.": {
				SRV: map[string]SRVEntry{
					"_http._tcp":  {Port: 80},
					"_https._tcp": {Port: 443},
				},
			},
		},
	}
	incoming := ZoneFile{
		Records: map[string]RecordSet{
			"example.com.": {
				SRV: map[string]SRVEntry{
					"_https._tcp": {Port: 8443}, // update
					"_smtp._tcp":  {Port: 25},   // new
				},
			},
		},
	}
	merged, err := Merge(existing, incoming)
	if err != nil {
		t.Fatalf("merge error: %v", err)
	}
	srv := merged.Records["example.com."].SRV
	if srv["_http._tcp"].Port != 80 {
		t.Error("_http._tcp should be preserved")
	}
	if srv["_https._tcp"].Port != 8443 {
		t.Error("_https._tcp should be updated to 8443")
	}
	if srv["_smtp._tcp"].Port != 25 {
		t.Error("_smtp._tcp should be added")
	}
}

// --- ValidateZoneContainment tests ---

func TestValidateZoneContainment_ApexAllowed(t *testing.T) {
	zf := ZoneFile{Records: map[string]RecordSet{
		"example.com.": {A: &ARecord{IPv4: "1.2.3.4"}},
	}}
	if errs := ValidateZoneContainment(zf, "example.com"); errs != nil {
		t.Errorf("apex hostname should be allowed: %v", errs)
	}
}

func TestValidateZoneContainment_SubdomainAllowed(t *testing.T) {
	zf := ZoneFile{Records: map[string]RecordSet{
		"www.example.com.":      {A: &ARecord{IPv4: "1.2.3.4"}},
		"deep.sub.example.com.": {A: &ARecord{IPv4: "2.3.4.5"}},
	}}
	if errs := ValidateZoneContainment(zf, "example.com"); errs != nil {
		t.Errorf("subdomain hostnames should be allowed: %v", errs)
	}
}

func TestValidateZoneContainment_OutsideDomainRejected(t *testing.T) {
	zf := ZoneFile{Records: map[string]RecordSet{
		"www.example.com.": {A: &ARecord{IPv4: "1.2.3.4"}},
		"evil.com.":        {A: &ARecord{IPv4: "9.9.9.9"}},
	}}
	errs := ValidateZoneContainment(zf, "example.com")
	if errs == nil {
		t.Fatal("expected containment error for out-of-zone hostname")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Field, "evil.com") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected evil.com to be flagged, got: %v", errs)
	}
}

func TestValidateZoneContainment_TrailingDotHandled(t *testing.T) {
	// Both with and without trailing dot should be accepted for the apex.
	for _, host := range []string{"example.com.", "example.com"} {
		zf := ZoneFile{Records: map[string]RecordSet{
			host: {A: &ARecord{IPv4: "1.2.3.4"}},
		}}
		if errs := ValidateZoneContainment(zf, "example.com"); errs != nil {
			t.Errorf("hostname %q should be accepted: %v", host, errs)
		}
	}
}

func TestValidateZoneContainment_EmptyRecordsOK(t *testing.T) {
	zf := ZoneFile{Serial: 1}
	if errs := ValidateZoneContainment(zf, "example.com"); errs != nil {
		t.Errorf("zone with no records should pass containment check: %v", errs)
	}
}

// --- ExtractRawDataFQDNs tests ---

func TestExtractRawDataFQDNs_BasicRecords(t *testing.T) {
	data := []byte("+host.example.com:1.2.3.4:300\n" +
		"=ptr.example.com:1.2.3.5:300\n" +
		"Caliases.example.com:host.example.com:300\n")
	fqdns := ExtractRawDataFQDNs(data)
	want := map[string]bool{
		"host.example.com":    true,
		"ptr.example.com":     true,
		"aliases.example.com": true,
	}
	for _, f := range fqdns {
		if !want[f] {
			t.Errorf("unexpected FQDN %q", f)
		}
		delete(want, f)
	}
	for f := range want {
		t.Errorf("missing expected FQDN %q", f)
	}
}

func TestExtractRawDataFQDNs_SkipsCommentsAndLocations(t *testing.T) {
	data := []byte("# comment\n%df:0.0.0.0/0\n\n+host.example.com:1.2.3.4:300\n")
	fqdns := ExtractRawDataFQDNs(data)
	if len(fqdns) != 1 || fqdns[0] != "host.example.com" {
		t.Errorf("expected [host.example.com], got %v", fqdns)
	}
}

func TestExtractRawDataFQDNs_Empty(t *testing.T) {
	fqdns := ExtractRawDataFQDNs([]byte("# only comments\n%df\n"))
	if len(fqdns) != 0 {
		t.Errorf("expected no FQDNs, got %v", fqdns)
	}
}

func TestMerge_PatchOnNonExistent(t *testing.T) {
	// PATCH on missing zone: merge with empty ZoneFile creates the zone.
	incoming := ZoneFile{
		TTL:     300,
		Records: map[string]RecordSet{
			"www.example.com.": {A: &ARecord{IPv4: "1.2.3.4"}},
		},
	}
	merged, err := Merge(ZoneFile{}, incoming)
	if err != nil {
		t.Fatalf("merge error: %v", err)
	}
	if merged.TTL != 300 {
		t.Errorf("TTL = %d, want 300", merged.TTL)
	}
	if merged.Records["www.example.com."].A.IPv4 != "1.2.3.4" {
		t.Error("record should be created")
	}
}
