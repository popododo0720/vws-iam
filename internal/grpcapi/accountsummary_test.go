package grpcapi_test

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// summaryQuotas are the quotas GetAccountSummary reports: the AWS
// defaults VWS enforces.
var summaryQuotas = map[string]int{
	"AccessKeysPerUserQuota":        2,
	"AttachedPoliciesPerGroupQuota": 10,
	"AttachedPoliciesPerRoleQuota":  10,
	"AttachedPoliciesPerUserQuota":  10,
	"GroupPolicySizeQuota":          5120,
	"GroupsPerUserQuota":            10,
	"PolicySizeQuota":               6144,
	"RolePolicySizeQuota":           10240,
	"UserPolicySizeQuota":           2048,
	"VersionsPerPolicyQuota":        5,
}

// summaryOmitted are the AWS SummaryMap keys VWS cannot compute (#268).
var summaryOmitted = []string{
	"UsersQuota", "GroupsQuota", "RolesQuota", "PoliciesQuota", "InstanceProfilesQuota",
	"PolicyVersionsInUse", "PolicyVersionsInUseQuota", "AssumeRolePolicySizeQuota",
	"ServerCertificates", "ServerCertificatesQuota", "SigningCertificatesPerUserQuota",
	"AccountSigningCertificatesPresent", "Providers", "AccountMFAEnabled",
	"AccountPasswordPresent", "GlobalEndpointTokenVersion",
}

// wantSummary builds the expected SummaryMap: the quotas and counts.
func wantSummary(counts map[string]int) map[string]int {
	out := maps.Clone(summaryQuotas)
	maps.Copy(out, counts)
	return out
}

// checkSummary fails unless got is exactly want and holds none of the
// omitted keys.
func checkSummary(t *testing.T, got, want map[string]int) {
	t.Helper()
	if !maps.Equal(got, want) {
		t.Fatalf("SummaryMap = %v, want %v", got, want)
	}
	for _, k := range summaryOmitted {
		if _, ok := got[k]; ok {
			t.Fatalf("SummaryMap has %s = %d, a key VWS cannot compute (#268)", k, got[k])
		}
	}
}

var summarySeal = iam.Sealed{KeyID: "k1", Ciphertext: []byte{1}}

// fidoFor returns a FIDO security key registered to user (uid) with a
// credential id derived from n.
func fidoFor(user, uid string, n byte, now time.Time) iam.FidoDevice {
	cred := []byte(strings.Repeat(string(rune('a'+n)), 16))
	return iam.FidoDevice{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, ID: iam.FidoID(cred), UserName: user, UserUID: uid,
		Label: "key", CredentialID: cred, PublicKey: []byte{1}, EnableTime: now,
	}
}

// TestGetAccountSummary: an empty account reports zero usage and the
// enforced quotas; after seeding, each count matches the project's
// entities (another project's never count), MFA devices count virtual
// devices and owned security keys, MFADevicesInUse the assigned ones;
// another replica reports the same and the call writes nothing. On both
// store backends.
func TestGetAccountSummary(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			zero := map[string]int{
				"Users": 0, "Groups": 0, "Roles": 0, "Policies": 0, "InstanceProfiles": 0,
				"MFADevices": 0, "MFADevicesInUse": 0, "AccountAccessKeysPresent": 0,
			}
			got, err := e.api.GetAccountSummary(ctx, proj)
			if err != nil {
				t.Fatal(err)
			}
			checkSummary(t, got, wantSummary(zero))

			seedDetails(t, b)
			sb := store.Scoped(b, proj)
			alice, err := store.Get[iam.User](ctx, sb, "alice")
			if err != nil {
				t.Fatal(err)
			}
			bob, err := store.Get[iam.User](ctx, sb, "bob")
			if err != nil {
				t.Fatal(err)
			}
			meta := func() iam.Meta { return iam.Meta{UID: iam.NewUID(), Generation: 1} }
			for _, obj := range []iam.Object{
				iam.MfaDevice{Meta: meta(), Name: "spare", Created: now, Seed: summarySeal},
				iam.MfaDevice{
					Meta: meta(), Name: "phone", Created: now, Seed: summarySeal,
					UserName: "alice", Enabled: true, EnableTime: now,
				},
				fidoFor("Bob", bob.Object.UID, 0, now),
				// Not owned: the user is gone, or was created again.
				fidoFor("ghost", iam.NewUID(), 1, now),
				fidoFor("alice", iam.NewUID(), 2, now),
				// A user's key is not the root user's.
				iam.AccessKey{
					Meta: meta(), ID: "AKIAAAAAAAAAAAAAAAAA", UserName: "alice",
					Status: iam.KeyActive, Created: now, Secret: summarySeal,
				},
			} {
				if _, err := store.Create(ctx, sb, obj); err != nil {
					t.Fatal(err)
				}
			}
			// Another project's entities never count.
			if _, err := store.Create(ctx, store.Scoped(b, "other"), iam.User{
				Meta: meta(), Name: "carol", ID: iam.NewUniqueID("AIDA"), Created: now,
			}); err != nil {
				t.Fatal(err)
			}
			want := wantSummary(map[string]int{
				"Users": 2, "Groups": 2, "Roles": 2, "Policies": 2, "InstanceProfiles": 2,
				"MFADevices": 3, "MFADevicesInUse": 2, "AccountAccessKeysPresent": 0,
			})
			for _, replica := range []*env{e, newEnvOn(t, b, &now)} {
				got, err := replica.api.GetAccountSummary(ctx, proj)
				if err != nil {
					t.Fatal(err)
				}
				checkSummary(t, got, want)
			}
			after, err := store.Get[iam.User](ctx, sb, "alice")
			if err != nil {
				t.Fatal(err)
			}
			if after.Version != alice.Version {
				t.Fatalf("summary wrote alice: version %q, want %q", after.Version, alice.Version)
			}
			got, err = e.api.GetAccountSummary(ctx, "other")
			if err != nil {
				t.Fatal(err)
			}
			if got["Users"] != 1 || got["Policies"] != 1 || got["Groups"] != 0 {
				t.Fatalf("other: Users %d, Policies %d, Groups %d; want 1, 1, 0", got["Users"], got["Policies"], got["Groups"])
			}
		})
	}
}

// TestGetAccountSummaryRootKeys: AccountAccessKeysPresent is 1 exactly
// when the root user has a key that is not pending, active or not.
func TestGetAccountSummaryRootKeys(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status iam.KeyStatus
		want   int
	}{
		{"active", iam.KeyActive, 1},
		{"inactive", iam.KeyInactive, 1},
		{"pending", iam.KeyPending, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := memstore.New()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			if _, err := store.Create(t.Context(), store.Scoped(b, proj), iam.AccessKey{
				Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, ID: "AKIABBBBBBBBBBBBBBBB",
				Root: true, Status: tc.status, Created: now, Secret: summarySeal,
			}); err != nil {
				t.Fatal(err)
			}
			got, err := e.api.GetAccountSummary(t.Context(), proj)
			if err != nil {
				t.Fatal(err)
			}
			if got["AccountAccessKeysPresent"] != tc.want {
				t.Fatalf("AccountAccessKeysPresent = %d, want %d", got["AccountAccessKeysPresent"], tc.want)
			}
		})
	}
}

// TestGetAccountSummaryRenaming: a user in an in-flight rename, stored
// under both names, counts once.
func TestGetAccountSummaryRenaming(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	sb := store.Scoped(b, proj)
	for _, u := range []iam.User{
		{Name: "old", RenameState: iam.RenameState{RenameTo: "new", RenameStarted: now}},
		{Name: "new", RenameState: iam.RenameState{RenamedFrom: "old", RenameStarted: now}},
	} {
		u.Meta = iam.Meta{UID: iam.NewUID(), Generation: 1}
		u.ID, u.Created = iam.NewUniqueID("AIDA"), now
		if _, err := store.CreateMarked(t.Context(), sb, u); err != nil {
			t.Fatal(err)
		}
	}
	got, err := e.api.GetAccountSummary(t.Context(), proj)
	if err != nil {
		t.Fatal(err)
	}
	if got["Users"] != 1 {
		t.Fatalf("Users = %d, want 1", got["Users"])
	}
}

// TestGetAccountSummaryErrors: a bad project is ValidationError before
// any store access, and a store failure on any kind read is
// ServiceFailure without backend detail, never a partial map.
func TestGetAccountSummaryErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	seedDetails(t, b)
	for _, pid := range []string{"", "Bad_Project", "a/b", strings.Repeat("p", 200)} {
		broken := newEnvOn(t, failingList{b, iam.KindUser, errors.New("backend exploded")}, &now)
		got, err := broken.api.GetAccountSummary(t.Context(), pid)
		wantAWS(t, err, codes.InvalidArgument, "ValidationError")
		if got != nil {
			t.Fatalf("project %q: SummaryMap %v with an error", pid, got)
		}
	}
	for _, k := range []iam.Kind{
		iam.KindUser, iam.KindGroup, iam.KindRole, iam.KindPolicy, iam.KindInstanceProfile,
		iam.KindMfaDevice, iam.KindFidoDevice, iam.KindAccessKey,
	} {
		broken := newEnvOn(t, failingList{b, k, errors.New("backend exploded")}, &now)
		got, err := broken.api.GetAccountSummary(t.Context(), proj)
		wantAWS(t, err, codes.Internal, "ServiceFailure")
		if got != nil || strings.Contains(err.Error(), "backend exploded") {
			t.Fatalf("%s: SummaryMap %v, error %v; want no map and no backend detail", k, got, err)
		}
	}
}

// TestGetAccountSummaryCanceled: a request whose context is canceled is
// Canceled, not a SummaryMap.
func TestGetAccountSummaryCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.api.GetAccountSummary(ctx, proj); status.Code(err) != codes.Canceled {
		t.Fatalf("canceled request: %v, want Canceled", err)
	}
}
