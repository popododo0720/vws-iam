package iam

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// The AWS limits for tags on an IAM resource.
const (
	// MaxPolicyTags is the AWS limit of tags per IAM policy.
	MaxPolicyTags = 50
	// MaxMFADeviceTags is the AWS limit of tags per IAM virtual MFA device.
	MaxMFADeviceTags = 50
	// MaxTagKeyLen is the AWS limit of a tag key, in characters.
	MaxTagKeyLen = 128
	// MaxTagValueLen is the AWS limit of a tag value, in characters.
	MaxTagValueLen = 256
)

// tagAlphabet is the AWS tag character class: letters, separators, numbers
// and _ . : / = + - @.
const tagAlphabet = `[\p{L}\p{Z}\p{N}_.:/=+\-@]`

var (
	tagKeyRE   = regexp.MustCompile("^" + tagAlphabet + "+$")
	tagValueRE = regexp.MustCompile("^" + tagAlphabet + "*$")
)

// TagError reports an invalid tag, with an AWS-shaped explanation. It is not
// an ErrInvalid: the gRPC edge answers it with the AWS InputError code, not
// with the ValidationError code a malformed request field gets.
type TagError struct{ msg string }

func (e *TagError) Error() string { return e.msg }

func tagError(format string, a ...any) error { return &TagError{msg: fmt.Sprintf(format, a...)} }

// reservedTagPrefix is the tag key and value prefix AWS reserves.
const reservedTagPrefix = "aws:"

// CheckTagKey reports whether key is an AWS tag key: 1 to 128 characters of
// tagAlphabet, not beginning with aws:.
func CheckTagKey(key string) error {
	if n := utf8.RuneCountInString(key); n < 1 || n > MaxTagKeyLen {
		return tagError("tag key must be 1 to %d characters, got %d", MaxTagKeyLen, n)
	}
	if !tagKeyRE.MatchString(key) {
		return tagError("tag key %q has a character outside the allowed alphabet", key)
	}
	if strings.HasPrefix(strings.ToLower(key), reservedTagPrefix) {
		return tagError("tag key %q begins with the reserved prefix %q", key, reservedTagPrefix)
	}
	return nil
}

// CheckTagValue reports whether value is an AWS tag value: 0 to 256
// characters of tagAlphabet, not beginning with aws:.
func CheckTagValue(value string) error {
	if n := utf8.RuneCountInString(value); n > MaxTagValueLen {
		return tagError("tag value must be at most %d characters, got %d", MaxTagValueLen, n)
	}
	if !tagValueRE.MatchString(value) {
		return tagError("tag value %q has a character outside the allowed alphabet", value)
	}
	if strings.HasPrefix(strings.ToLower(value), reservedTagPrefix) {
		return tagError("tag value %q begins with the reserved prefix %q", value, reservedTagPrefix)
	}
	return nil
}

// CheckTag reports whether the key/value pair is a valid AWS tag.
func CheckTag(key, value string) error {
	if err := CheckTagKey(key); err != nil {
		return err
	}
	return CheckTagValue(value)
}

// CheckTags reports the first invalid tag of tags. It does not check the
// number of tags.
func CheckTags(tags map[string]string) error {
	for key, value := range tags {
		if err := CheckTag(key, value); err != nil {
			return err
		}
	}
	return nil
}
