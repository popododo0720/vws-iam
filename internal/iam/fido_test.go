package iam_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
)

func fidoSample() iam.FidoDevice {
	cred := []byte("credential-id-0001")
	return iam.FidoDevice{
		ID: iam.FidoID(cred), UserName: "Bob", UserUID: "u-1", Label: "testFidoKey",
		CredentialID: cred, PublicKey: []byte{0xa5},
		AAGUID: "cb69481e-8ff7-4039-93ec-0a2729a154a8", EnableTime: time.Unix(1_800_000_000, 0).UTC(),
		Certifications: map[string]string{"FIDO": "L1", "FIDO-FIPS-140-2": "L2"},
	}
}

func TestFidoDeviceValidate(t *testing.T) {
	if err := fidoSample().Validate(); err != nil {
		t.Fatalf("valid sample: %v", err)
	}
	bad := map[string]func(d *iam.FidoDevice){
		"id not of credential": func(d *iam.FidoDevice) { d.ID = iam.FidoID([]byte("another-credential")) },
		"id lowercase":         func(d *iam.FidoDevice) { d.ID = strings.ToLower(d.ID) },
		"no user":              func(d *iam.FidoDevice) { d.UserName = "" },
		"user 65":              func(d *iam.FidoDevice) { d.UserName = strings.Repeat("u", 65) },
		"user slash":           func(d *iam.FidoDevice) { d.UserName = "a/b" },
		"no user uid":          func(d *iam.FidoDevice) { d.UserUID = "" },
		"no label":             func(d *iam.FidoDevice) { d.Label = "" },
		"label 65":             func(d *iam.FidoDevice) { d.Label = strings.Repeat("l", 65) },
		"label slash":          func(d *iam.FidoDevice) { d.Label = "a/b" },
		"credential 15 bytes": func(d *iam.FidoDevice) {
			d.CredentialID = make([]byte, iam.MinFidoCredentialIDLen-1)
			d.ID = iam.FidoID(d.CredentialID)
		},
		"credential 1024 bytes": func(d *iam.FidoDevice) {
			d.CredentialID = make([]byte, iam.MaxFidoCredentialIDLen+1)
			d.ID = iam.FidoID(d.CredentialID)
		},
		"no public key":      func(d *iam.FidoDevice) { d.PublicKey = nil },
		"public key too big": func(d *iam.FidoDevice) { d.PublicKey = make([]byte, iam.MaxFidoPublicKeyLen+1) },
		"aaguid":             func(d *iam.FidoDevice) { d.AAGUID = "not-a-uuid" },
		"no enable time":     func(d *iam.FidoDevice) { d.EnableTime = time.Time{} },
		"cert key 129": func(d *iam.FidoDevice) {
			d.Certifications = map[string]string{strings.Repeat("k", 129): "L1"}
		},
		"cert value 33": func(d *iam.FidoDevice) {
			d.Certifications = map[string]string{"FIDO": strings.Repeat("v", 33)}
		},
		"cert empty value":  func(d *iam.FidoDevice) { d.Certifications = map[string]string{"FIDO": ""} },
		"cert control char": func(d *iam.FidoDevice) { d.Certifications = map[string]string{"FIDO\n": "L1"} },
		"cert outside latin1": func(d *iam.FidoDevice) {
			d.Certifications = map[string]string{"FIDO": "L\u0100"}
		},
		"17 certs": func(d *iam.FidoDevice) {
			d.Certifications = map[string]string{}
			for i := range iam.MaxFidoCertifications + 1 {
				d.Certifications[strings.Repeat("k", i+1)] = "L1"
			}
		},
	}
	for name, mut := range bad {
		d := fidoSample()
		mut(&d)
		if err := d.Validate(); !errors.Is(err, iam.ErrInvalid) {
			t.Errorf("%s: Validate = %v, want ErrInvalid", name, err)
		}
	}
	edge := fidoSample()
	edge.UserName, edge.Label = strings.Repeat("u", 64), strings.Repeat("l", 64)
	edge.CredentialID = make([]byte, iam.MaxFidoCredentialIDLen)
	edge.ID, edge.AAGUID = iam.FidoID(edge.CredentialID), ""
	edge.Certifications = map[string]string{strings.Repeat("k", 128): strings.Repeat("v", 32)}
	if err := edge.Validate(); err != nil {
		t.Fatalf("boundary values: %v", err)
	}
	// The limits count characters, not UTF-8 bytes: Latin-1 letters
	// above U+007F are two bytes each.
	edge.Certifications = map[string]string{strings.Repeat("\u00e9", 128): strings.Repeat("\u00e9", 32)}
	if err := edge.Validate(); err != nil {
		t.Fatalf("Latin-1 boundary values: %v", err)
	}
	edge.Certifications = map[string]string{"FIDO": strings.Repeat("\u00e9", 33)}
	if err := edge.Validate(); !errors.Is(err, iam.ErrInvalid) {
		t.Fatalf("33 Latin-1 characters: %v, want ErrInvalid", err)
	}
}

func TestFidoID(t *testing.T) {
	a, b := iam.FidoID([]byte("credential-a")), iam.FidoID([]byte("credential-b"))
	if len(a) != iam.FidoIDLen || a == b || a != iam.FidoID([]byte("credential-a")) {
		t.Fatalf("FidoID not a stable %d-char digest: %q %q", iam.FidoIDLen, a, b)
	}
}

func TestFidoDeviceARN(t *testing.T) {
	d := fidoSample()
	serial := iam.FidoDeviceARN("proj-a", d)
	if want := "arn:vws:iam::proj-a:u2f/user/Bob/testFidoKey-" + d.ID; serial != want {
		t.Fatalf("serial %q, want %q", serial, want)
	}
	user, id, ok := iam.SplitFidoDeviceARN("proj-a", serial)
	if !ok || user != "Bob" || id != d.ID {
		t.Fatalf("split %q = %q %q %v", serial, user, id, ok)
	}
	dashed := d
	dashed.Label = "key-with-dashes"
	if _, id, ok := iam.SplitFidoDeviceARN("proj-a", iam.FidoDeviceARN("proj-a", dashed)); !ok || id != d.ID {
		t.Fatalf("label with dashes: %q %v", id, ok)
	}
	long := d
	long.UserName, long.Label = strings.Repeat("u", 64), strings.Repeat("l", 64)
	if _, _, ok := iam.SplitFidoDeviceARN("proj-a", iam.FidoDeviceARN("proj-a", long)); !ok {
		t.Fatal("longest user and label must split")
	}
	for _, s := range []string{
		"",
		"arn:vws:iam::proj-b:u2f/user/Bob/testFidoKey-" + d.ID,      // other account
		"arn:aws:iam::proj-a:u2f/user/Bob/testFidoKey-" + d.ID,      // other partition
		"arn:vws:iam::proj-a:mfa/Bob",                               // virtual device
		"arn:vws:iam::proj-a:u2f/root/testFidoKey-" + d.ID,          // root key
		"arn:vws:iam::proj-a:u2f/user/Bob/testFidoKey-R1234",        // short id
		"arn:vws:iam::proj-a:u2f/user/Bob/" + d.ID,                  // no label
		"arn:vws:iam::proj-a:u2f/user/Bob/-" + d.ID,                 // empty label
		"arn:vws:iam::proj-a:u2f/user/Bob/team/testFidoKey-" + d.ID, // extra segment
		"arn:vws:iam::proj-a:u2f/user//testFidoKey-" + d.ID,         // empty user
		"arn:vws:iam::proj-a:u2f/user/Bob/testFidoKey-" + strings.ToLower(d.ID),
		"arn:vws:iam::proj-a:u2f/user/Bob/" + strings.Repeat("l", 300) + "-" + d.ID,
	} {
		if u, id, ok := iam.SplitFidoDeviceARN("proj-a", s); ok {
			t.Errorf("SplitFidoDeviceARN(%q) = %q %q true, want false", s, u, id)
		}
	}
}
