package grpcapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

func keyPairMissing() error {
	return fail(codes.NotFound, "RESOURCE_NOT_FOUND", "InvalidKeyPair.NotFound", "key pair does not exist")
}

func keyPairDuplicate() error {
	return fail(codes.AlreadyExists, "ALREADY_EXISTS", "InvalidKeyPair.Duplicate", "key pair already exists")
}

func keyPairInput(keyName, region string) error {
	if !iam.ValidKeyPairName(keyName) || !iam.ValidKeyPairRegion(region) {
		return fail(codes.InvalidArgument, "INVALID_SPEC", "InvalidParameterValue", "invalid key name or region")
	}
	return nil
}

func keyPairProto(pid string, v store.Versioned[iam.KeyPair]) *iamv1.KeyPair {
	k := v.Object
	typ := iamv1.KeyPairType_KEY_PAIR_TYPE_RSA
	if k.KeyType == iam.KeyPairED25519 {
		typ = iamv1.KeyPairType_KEY_PAIR_TYPE_ED25519
	}
	return &iamv1.KeyPair{
		Name: name(pid, "keyPairs", k.ID), Uid: k.UID, Generation: k.Generation, Etag: v.Version,
		Labels: labels(k.Labels), CreateTime: ts(k.Created), UpdateTime: ts(k.Created), DeleteTime: ts(k.Deleted),
		Spec: &iamv1.KeyPairSpec{KeyName: k.Name, Region: k.Region, PublicKey: k.PublicKey},
		Status: &iamv1.KeyPairStatus{
			Observed: ready(k.Generation), FingerprintSha256: k.FingerprintSHA256, KeyType: typ,
		},
	}
}

func (s *Server) publicKeyPair(keyName, region, material string) (iam.KeyPair, error) {
	k := iam.KeyPair{
		ID: iam.NewKeyPairID(), Name: keyName, Region: region,
	}
	pub, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(material))
	if err == nil && len(options) == 0 && len(strings.TrimSpace(string(rest))) == 0 &&
		!strings.ContainsAny(strings.TrimSpace(material), "\r\n") {
		k.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
		sum := sha256.Sum256(pub.Marshal())
		k.FingerprintSHA256 = hex.EncodeToString(sum[:])
		switch pub.Type() {
		case ssh.KeyAlgoRSA:
			k.KeyType = iam.KeyPairRSA
		case ssh.KeyAlgoED25519:
			k.KeyType = iam.KeyPairED25519
		}
		k.Created = s.now().UTC()
		err = k.Validate()
		if err == nil {
			return k, nil
		}
	}
	return k, fail(codes.InvalidArgument, "INVALID_SPEC", "InvalidKey.Format", "invalid OpenSSH public key")
}

// Key pair authorization follows the other IAM resource services: the gateway
// calls Authenticate and Authorize before invoking this internal RPC service.
func (s *Server) GetKeyPair(ctx context.Context, req *iamv1.GetKeyPairRequest) (*iamv1.KeyPair, error) {
	pid, id, err := child(req.GetName(), "keyPairs")
	if err != nil {
		return nil, err
	}
	v, err := store.Get[iam.KeyPair](ctx, s.project(pid).b, id)
	if errors.Is(err, store.ErrNotFound) || err == nil && (v.Object.Pending || !v.Object.Deleted.IsZero()) {
		err = keyPairMissing()
	}
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return keyPairProto(pid, v), nil
}

func (s *Server) ListKeyPairs(
	ctx context.Context, req *iamv1.ListKeyPairsRequest,
) (*iamv1.ListKeyPairsResponse, error) {
	pid, err := parent(req.GetParent())
	if err != nil {
		return nil, err
	}
	if req.GetRegion() != "" && !iam.ValidKeyPairRegion(req.GetRegion()) || len(req.GetKeyNames()) > 200 {
		return nil, invalidSpec("invalid region or more than 200 key names")
	}
	for _, n := range req.GetKeyNames() {
		if err := keyPairInput(n, "region"); err != nil {
			return nil, err
		}
	}
	all, err := store.List[iam.KeyPair](ctx, s.project(pid).b)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	all = slices.DeleteFunc(all, func(v store.Versioned[iam.KeyPair]) bool {
		k := v.Object
		return k.Pending || !k.Deleted.IsZero() || req.GetRegion() != "" && req.GetRegion() != k.Region ||
			len(req.GetKeyNames()) != 0 && !slices.Contains(req.GetKeyNames(), k.Name)
	})
	items, next, err := page(all, func(v store.Versioned[iam.KeyPair]) string {
		return v.Object.ID
	}, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &iamv1.ListKeyPairsResponse{NextPageToken: next}
	for _, v := range items {
		out.KeyPairs = append(out.KeyPairs, keyPairProto(pid, v))
	}
	return out, nil
}

func (s *Server) CreateKeyPair(
	ctx context.Context, req *iamv1.CreateKeyPairRequest,
) (*iamv1.CreateKeyPairResponse, error) {
	pid, err := parent(req.GetParent())
	if err != nil {
		return nil, err
	}
	if err := keyPairInput(req.GetKeyName(), req.GetRegion()); err != nil {
		return nil, err
	}
	var private any
	switch req.GetKeyType() {
	case iamv1.KeyPairType_KEY_PAIR_TYPE_UNSPECIFIED, iamv1.KeyPairType_KEY_PAIR_TYPE_RSA:
		private, err = rsa.GenerateKey(rand.Reader, 2048)
	case iamv1.KeyPairType_KEY_PAIR_TYPE_ED25519:
		_, private, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, invalidSpec("key_type must be RSA or ED25519")
	}
	if err != nil {
		return nil, toStatus(ctx, fmt.Errorf("generate key pair: %w", err))
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		return nil, toStatus(ctx, fmt.Errorf("key pair signer: %w", err))
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		return nil, toStatus(ctx, fmt.Errorf("marshal private key: %w", err))
	}
	k, err := s.publicKeyPair(req.GetKeyName(), req.GetRegion(), string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if err != nil {
		return nil, err
	}
	k.Labels = labels(req.GetLabels())
	v, replay, err := s.project(pid).storeKeyPair(ctx, k, newOnce(pid, "CreateKeyPair", req.GetRequestId(), req))
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	if replay {
		return nil, keyPairDuplicate()
	}
	return &iamv1.CreateKeyPairResponse{
		KeyPair: keyPairProto(pid, v), PrivateKeyMaterial: string(pem.EncodeToMemory(block)),
	}, nil
}

func (s *Server) ImportKeyPair(
	ctx context.Context, req *iamv1.ImportKeyPairRequest,
) (*longrunningpb.Operation, error) {
	pid, err := parent(req.GetParent())
	if err != nil {
		return nil, err
	}
	if err := keyPairInput(req.GetKeyName(), req.GetRegion()); err != nil {
		return nil, err
	}
	if op, err := s.replay(ctx, pid, "ImportKeyPair", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	k, err := s.publicKeyPair(req.GetKeyName(), req.GetRegion(), req.GetPublicKey())
	if err != nil {
		return nil, err
	}
	k.Labels = labels(req.GetLabels())
	v, _, err := s.project(pid).storeKeyPair(ctx, k, newOnce(pid, "ImportKeyPair", req.GetRequestId(), req))
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	op, err := s.done(ctx, opArgs{
		project: pid, method: "ImportKeyPair", requestID: req.GetRequestId(), req: req,
		resource: name(pid, "keyPairs", v.Object.ID), verb: commonv1.OperationVerb_OPERATION_VERB_CREATE,
		generation: v.Object.Generation, response: keyPairProto(pid, v),
	})
	return op, toStatus(ctx, err)
}

// The pending create is committed only while the regional name scan's lock
// version still holds. An expired lease can never publish a duplicate name.
func (p project) storeKeyPair(
	ctx context.Context, k iam.KeyPair, o once,
) (store.Versioned[iam.KeyPair], bool, error) {
	pre, unlock, err := p.lockMembership(ctx)
	if err != nil {
		return store.Versioned[iam.KeyPair]{}, false, err
	}
	defer unlock()
	all, err := store.List[iam.KeyPair](ctx, p.b)
	if err != nil {
		return store.Versioned[iam.KeyPair]{}, false, err
	}
	for _, v := range all {
		if !v.Object.Pending {
			if err := o.check(v.Object.Meta); err != nil {
				if errors.Is(err, errApplied) {
					return v, true, nil
				}
				return v, false, err
			}
		}
	}
	for _, v := range all {
		if !v.Object.Pending && v.Object.Deleted.IsZero() && v.Object.Name == k.Name && v.Object.Region == k.Region {
			return v, false, keyPairDuplicate()
		}
	}
	k.UID, k.Generation, k.Created, k.Pending = iam.NewUID(), 1, p.now().UTC(), true
	v, err := store.Create(ctx, p.b, k)
	if err != nil {
		return store.Versioned[iam.KeyPair]{}, false, err
	}
	k.Pending = false
	o.record(&k.Meta)
	v, err = store.UpdateIf(ctx, p.b, k, v, pre)
	return store.Versioned[iam.KeyPair]{Object: k, Version: v}, false, err
}

func (s *Server) DeleteKeyPair(
	ctx context.Context, req *iamv1.DeleteKeyPairRequest,
) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetName(), "keyPairs")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	pre, unlock, err := p.lockMembership(ctx)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	defer unlock()
	if op, err := s.replay(ctx, pid, "DeleteKeyPair", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	o := newOnce(pid, "DeleteKeyPair", req.GetRequestId(), req)
	all, err := store.List[iam.KeyPair](ctx, p.b)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	var v store.Versioned[iam.KeyPair]
	applied := false
	for _, cur := range all {
		if !cur.Object.Pending {
			if err := o.check(cur.Object.Meta); err != nil {
				if !errors.Is(err, errApplied) {
					return nil, toStatus(ctx, err)
				}
				v, applied = cur, true
				break
			}
		}
	}
	if !applied {
		v, err = store.Get[iam.KeyPair](ctx, p.b, id)
		missing := errors.Is(err, store.ErrNotFound) || err == nil && (v.Object.Pending || !v.Object.Deleted.IsZero())
		switch {
		case missing && req.GetAllowMissing():
			v = store.Versioned[iam.KeyPair]{}
			err = nil
		case missing:
			err = keyPairMissing()
		case err == nil:
			err = checkEtag(req.GetEtag(), v.Version)
			if err == nil {
				v.Object.Deleted = s.now().UTC()
				o.record(&v.Object.Meta)
				v.Version, err = store.UpdateIf(ctx, p.b, v.Object, v.Version, pre)
			}
		}
	}
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp := &iamv1.KeyPair{Name: req.GetName()}
	if v.Object.ID != "" {
		resp = keyPairProto(pid, v)
	}
	op, err := s.done(ctx, opArgs{
		project: pid, method: "DeleteKeyPair", requestID: req.GetRequestId(), req: req,
		resource: req.GetName(), verb: commonv1.OperationVerb_OPERATION_VERB_DELETE,
		generation: v.Object.Generation, response: resp,
	})
	return op, toStatus(ctx, err)
}
