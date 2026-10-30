package grpcapi_test

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// TestGroupNameLength: CreateGroup accepts a group id of up to 128
// characters, like AWS GroupName, and the group stays addressable by Get,
// Update and Delete; 129 characters is InvalidArgument (ValidationError).
// User ids stay at 64 (#135).
func TestGroupNameLength(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.createUser(t, ctx, "alice")
	g128 := strings.Repeat("g", 128)
	g129 := strings.Repeat("g", 129)

	op, err := e.groups.CreateGroup(ctx, &iamv1.CreateGroupRequest{
		Parent: parentName, GroupId: g128,
		Group: &iamv1.Group{Spec: &iamv1.GroupSpec{Members: []string{parentName + "/users/alice"}}},
	})
	if err != nil {
		t.Fatalf("CreateGroup of 128: %v", err)
	}
	g := unpack(t, op, &iamv1.Group{})
	if want := parentName + "/groups/" + g128; g.GetName() != want {
		t.Fatalf("group name %q, want %q", g.GetName(), want)
	}
	got, err := e.groups.GetGroup(ctx, &iamv1.GetGroupRequest{Name: g.GetName()})
	if err != nil || got.GetName() != g.GetName() {
		t.Fatalf("GetGroup of 128: %v %v", got, err)
	}
	u, err := e.users.GetUser(ctx, &iamv1.GetUserRequest{Name: parentName + "/users/alice"})
	if err != nil || len(u.GetStatus().GetGroups()) != 1 || u.GetStatus().GetGroups()[0] != g.GetName() {
		t.Fatalf("membership %v %v", u.GetStatus(), err)
	}
	op, err = e.groups.UpdateGroup(ctx, &iamv1.UpdateGroupRequest{
		Group:      &iamv1.Group{Name: g.GetName(), Etag: got.GetEtag(), Spec: &iamv1.GroupSpec{}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.members"}},
	})
	if err != nil {
		t.Fatalf("UpdateGroup of 128: %v", err)
	}
	if up := unpack(t, op, &iamv1.Group{}); len(up.GetSpec().GetMembers()) != 0 {
		t.Fatalf("members after update %v", up.GetSpec().GetMembers())
	}
	if _, err := e.groups.DeleteGroup(ctx, &iamv1.DeleteGroupRequest{Name: g.GetName()}); err != nil {
		t.Fatalf("DeleteGroup of 128: %v", err)
	}
	_, err = e.groups.GetGroup(ctx, &iamv1.GetGroupRequest{Name: g.GetName()})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")

	// An upsert creates the group under the same limit.
	op, err = e.groups.UpdateGroup(ctx, &iamv1.UpdateGroupRequest{
		Group:      &iamv1.Group{Name: parentName + "/groups/" + g128, Spec: &iamv1.GroupSpec{}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.members"}}, AllowMissing: true,
	})
	if err != nil {
		t.Fatalf("UpdateGroup allow_missing of 128: %v", err)
	}
	if up := unpack(t, op, &iamv1.Group{}); up.GetName() != parentName+"/groups/"+g128 {
		t.Fatalf("upserted %q", up.GetName())
	}

	_, err = e.groups.CreateGroup(ctx, &iamv1.CreateGroupRequest{
		Parent: parentName, GroupId: g129, Group: &iamv1.Group{Spec: &iamv1.GroupSpec{}},
	})
	wantErr(t, err, codes.InvalidArgument, "INVALID_RESOURCE_ID", "ValidationError")
	_, err = e.groups.UpdateGroup(ctx, &iamv1.UpdateGroupRequest{
		Group:      &iamv1.Group{Name: parentName + "/groups/" + g129, Spec: &iamv1.GroupSpec{}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.members"}}, AllowMissing: true,
	})
	wantErr(t, err, codes.InvalidArgument, "INVALID_RESOURCE_ID", "ValidationError")

	// User ids stay at 64.
	e.createUser(t, ctx, strings.Repeat("u", 64))
	_, err = e.users.CreateUser(ctx, &iamv1.CreateUserRequest{
		Parent: parentName, UserId: strings.Repeat("u", 65), User: &iamv1.User{Spec: &iamv1.UserSpec{}},
	})
	wantErr(t, err, codes.InvalidArgument, "INVALID_RESOURCE_ID", "ValidationError")
}
