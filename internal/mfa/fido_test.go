package mfa_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/mfa"
	"github.com/popododo0720/vws-iam/internal/store"
)

func credential(id string) mfa.FidoCredential {
	return mfa.FidoCredential{
		ID: []byte(id), PublicKey: []byte{0xa5, 0x01, 0x02}, AAGUID: "cb69481e-8ff7-4039-93ec-0a2729a154a8", SignCount: 3,
		Certifications: map[string]string{"FIDO": "L1", "FIDO-FIPS-140-2": "L2"},
	}
}

func TestFidoRegisterAndGet(t *testing.T) {
	svc, _, clk := setup(t)
	ctx := context.Background()
	d, err := svc.RegisterFido(ctx, "Alice", "yubikey", credential("alice-credential-1"))
	if err != nil {
		t.Fatal(err)
	}
	serial := svc.FidoSerial(d)
	want := "arn:vws:iam::" + acct + ":u2f/user/alice/yubikey-" + iam.FidoID([]byte("alice-credential-1"))
	if serial != want {
		t.Fatalf("serial %q, want %q (the stored user name)", serial, want)
	}
	for _, user := range []string{"", "alice", "ALICE"} {
		got, err := svc.GetFido(ctx, serial, user)
		if err != nil {
			t.Fatalf("GetFido(user %q): %v", user, err)
		}
		if got.UserName != "alice" || !got.EnableTime.Equal(clk.t) || got.Certifications["FIDO"] != "L1" ||
			got.Certifications["FIDO-FIPS-140-2"] != "L2" || len(got.Certifications) != 2 {
			t.Fatalf("GetFido(user %q) = %+v", user, got)
		}
	}
}

func TestFidoGetNoSuchEntity(t *testing.T) {
	svc, b, _ := setup(t)
	ctx := context.Background()
	d, err := svc.RegisterFido(ctx, "alice", "yubikey", credential("alice-credential-1"))
	if err != nil {
		t.Fatal(err)
	}
	serial := svc.FidoSerial(d)
	virtual, err := svc.CreateVirtual(ctx, "alice-phone", "")
	if err != nil {
		t.Fatal(err)
	}
	other := mfa.New(b, nil, "999999999999", nil)
	cases := map[string]struct{ serial, user string }{
		"other user":      {serial, "bob"},
		"missing user":    {serial, "nobody"},
		"virtual device":  {virtual.SerialNumber, ""},
		"unregistered id": {strings.Replace(serial, d.ID, iam.FidoID([]byte("never-registered")), 1), ""},
		"other label":     {strings.Replace(serial, "yubikey-", "other-", 1), ""},
		"user in serial":  {strings.Replace(serial, "/alice/", "/bob/", 1), ""},
		"case of user":    {strings.Replace(serial, "/alice/", "/ALICE/", 1), ""},
		"root serial":     {"arn:vws:iam::" + acct + ":u2f/root/yubikey-" + d.ID, ""},
		"aws example":     {"arn:aws:iam::123456789012:u2f/root/testFidoKey-R1234", "Bob"},
		"empty":           {"", ""},
		"garbage":         {"not an arn", ""},
		"longer than 256": {serial + strings.Repeat("x", 256), ""},
	}
	for name, c := range cases {
		if _, err := svc.GetFido(ctx, c.serial, c.user); !errors.Is(err, mfa.ErrNotAssociated) {
			t.Errorf("%s: GetFido = %v, want ErrNotAssociated", name, err)
		}
	}
	if _, err := other.GetFido(ctx, serial, ""); !errors.Is(err, mfa.ErrNotAssociated) {
		t.Errorf("serial of another account: %v, want ErrNotAssociated", err)
	}
}

func TestFidoRegisterIdempotentAndDurable(t *testing.T) {
	svc, b, _ := setup(t)
	ctx := context.Background()
	d, err := svc.RegisterFido(ctx, "alice", "yubikey", credential("alice-credential-1"))
	if err != nil {
		t.Fatal(err)
	}
	// A retried registration and the same credential under another user
	// or label are refused and change nothing.
	for _, r := range []struct{ user, label string }{{"alice", "yubikey"}, {"alice", "spare"}, {"bob", "yubikey"}} {
		_, err := svc.RegisterFido(ctx, r.user, r.label, credential("alice-credential-1"))
		if !errors.Is(err, mfa.ErrEntityInUse) {
			t.Fatalf("re-register as %v: %v, want ErrEntityInUse", r, err)
		}
	}
	// A restart is a new Service on the same store.
	restarted := mfa.New(b, nil, acct, nil)
	got, err := restarted.GetFido(ctx, svc.FidoSerial(d), "alice")
	if err != nil || got.Label != "yubikey" || got.UID != d.UID {
		t.Fatalf("after restart: %+v %v", got, err)
	}
	all, err := restarted.ListFido(ctx, "")
	if err != nil || len(all) != 1 {
		t.Fatalf("after restart list: %d %v", len(all), err)
	}
}

func TestFidoConcurrentRegistrationWinsOnce(t *testing.T) {
	svc, _, _ := setup(t)
	ctx := context.Background()
	const n = 16
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		ok   int
		errs []error
	)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			user := []string{"alice", "bob"}[i%2]
			_, err := svc.RegisterFido(ctx, user, "key", credential("raced-credential-1"))
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				ok++
			} else if !errors.Is(err, mfa.ErrEntityInUse) {
				errs = append(errs, err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 || len(errs) != 0 {
		t.Fatalf("%d registrations won, unexpected errors %v; want exactly 1", ok, errs)
	}
	all, err := svc.ListFido(ctx, "")
	if err != nil || len(all) != 1 {
		t.Fatalf("stored %d devices (%v), want 1", len(all), err)
	}
}

func TestFidoRegisterRejectsHostileInput(t *testing.T) {
	svc, _, _ := setup(t)
	ctx := context.Background()
	_, err := svc.RegisterFido(ctx, "nobody", "key", credential("credential-nobody"))
	if !errors.Is(err, mfa.ErrNotAssociated) {
		t.Fatalf("missing user: %v, want ErrNotAssociated", err)
	}
	bad := map[string]func(label *string, c *mfa.FidoCredential){
		"empty label":      func(l *string, _ *mfa.FidoCredential) { *l = "" },
		"label 65":         func(l *string, _ *mfa.FidoCredential) { *l = strings.Repeat("l", 65) },
		"label slash":      func(l *string, _ *mfa.FidoCredential) { *l = "a/b" },
		"short credential": func(_ *string, c *mfa.FidoCredential) { c.ID = []byte("short") },
		"no public key":    func(_ *string, c *mfa.FidoCredential) { c.PublicKey = nil },
		"bad aaguid":       func(_ *string, c *mfa.FidoCredential) { c.AAGUID = "x" },
		"long certification": func(_ *string, c *mfa.FidoCredential) {
			c.Certifications = map[string]string{"FIDO": strings.Repeat("L", 33)}
		},
	}
	for name, mut := range bad {
		label, c := "key", credential("hostile-credential-1")
		mut(&label, &c)
		if _, err := svc.RegisterFido(ctx, "alice", label, c); !errors.Is(err, iam.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	if all, err := svc.ListFido(ctx, ""); err != nil || len(all) != 0 {
		t.Fatalf("hostile input stored %d devices (%v)", len(all), err)
	}
}

func TestFidoCertificationsAreCopied(t *testing.T) {
	svc, _, _ := setup(t)
	ctx := context.Background()
	c := credential("alice-credential-1")
	d, err := svc.RegisterFido(ctx, "alice", "key", c)
	if err != nil {
		t.Fatal(err)
	}
	c.Certifications["FIDO"] = "L3"
	got, err := svc.GetFido(ctx, svc.FidoSerial(d), "")
	if err != nil || got.Certifications["FIDO"] != "L1" {
		t.Fatalf("stored certifications follow the caller's map: %v %v", got.Certifications, err)
	}
}

func TestFidoListAndDeactivate(t *testing.T) {
	svc, b, _ := setup(t)
	ctx := context.Background()
	a1, err := svc.RegisterFido(ctx, "alice", "key1", credential("alice-credential-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterFido(ctx, "alice", "key2", credential("alice-credential-2")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterFido(ctx, "bob", "key1", credential("bob-credential-01")); err != nil {
		t.Fatal(err)
	}
	if l, err := svc.ListFido(ctx, "ALICE"); err != nil || len(l) != 2 {
		t.Fatalf("alice: %d %v", len(l), err)
	}
	serial := svc.FidoSerial(a1)
	if err := svc.DeactivateFido(ctx, "bob", serial); !errors.Is(err, mfa.ErrNotAssociated) {
		t.Fatalf("deactivate by another user: %v", err)
	}
	wrongLabel := strings.Replace(serial, "key1-", "key9-", 1)
	if err := svc.DeactivateFido(ctx, "alice", wrongLabel); !errors.Is(err, mfa.ErrNotAssociated) {
		t.Fatalf("deactivate with a wrong label: %v", err)
	}
	if err := svc.DeactivateFido(ctx, "alice", serial); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeactivateFido(ctx, "alice", serial); !errors.Is(err, mfa.ErrNotAssociated) {
		t.Fatalf("second deactivate: %v, want ErrNotAssociated", err)
	}
	if _, err := svc.GetFido(ctx, serial, ""); !errors.Is(err, mfa.ErrNotAssociated) {
		t.Fatalf("get after deactivate: %v", err)
	}
	if _, err := store.Get[iam.FidoDevice](ctx, b, a1.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("device still stored: %v", err)
	}
	// The credential can be registered again once removed.
	if _, err := svc.RegisterFido(ctx, "alice", "key1", credential("alice-credential-1")); err != nil {
		t.Fatalf("re-register after deactivate: %v", err)
	}
}
