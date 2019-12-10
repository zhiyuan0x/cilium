// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/type/matcher/string.proto

package envoy_type_matcher

import (
	fmt "fmt"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// Specifies the way to match a string.
// [#next-free-field: 6]
type StringMatcher struct {
	// Types that are valid to be assigned to MatchPattern:
	//	*StringMatcher_Exact
	//	*StringMatcher_Prefix
	//	*StringMatcher_Suffix
	//	*StringMatcher_Regex
	//	*StringMatcher_SafeRegex
	MatchPattern         isStringMatcher_MatchPattern `protobuf_oneof:"match_pattern"`
	XXX_NoUnkeyedLiteral struct{}                     `json:"-"`
	XXX_unrecognized     []byte                       `json:"-"`
	XXX_sizecache        int32                        `json:"-"`
}

func (m *StringMatcher) Reset()         { *m = StringMatcher{} }
func (m *StringMatcher) String() string { return proto.CompactTextString(m) }
func (*StringMatcher) ProtoMessage()    {}
func (*StringMatcher) Descriptor() ([]byte, []int) {
	return fileDescriptor_1dc62c75a0f154e3, []int{0}
}

func (m *StringMatcher) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StringMatcher.Unmarshal(m, b)
}
func (m *StringMatcher) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StringMatcher.Marshal(b, m, deterministic)
}
func (m *StringMatcher) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StringMatcher.Merge(m, src)
}
func (m *StringMatcher) XXX_Size() int {
	return xxx_messageInfo_StringMatcher.Size(m)
}
func (m *StringMatcher) XXX_DiscardUnknown() {
	xxx_messageInfo_StringMatcher.DiscardUnknown(m)
}

var xxx_messageInfo_StringMatcher proto.InternalMessageInfo

type isStringMatcher_MatchPattern interface {
	isStringMatcher_MatchPattern()
}

type StringMatcher_Exact struct {
	Exact string `protobuf:"bytes,1,opt,name=exact,proto3,oneof"`
}

type StringMatcher_Prefix struct {
	Prefix string `protobuf:"bytes,2,opt,name=prefix,proto3,oneof"`
}

type StringMatcher_Suffix struct {
	Suffix string `protobuf:"bytes,3,opt,name=suffix,proto3,oneof"`
}

type StringMatcher_Regex struct {
	Regex string `protobuf:"bytes,4,opt,name=regex,proto3,oneof"`
}

type StringMatcher_SafeRegex struct {
	SafeRegex *RegexMatcher `protobuf:"bytes,5,opt,name=safe_regex,json=safeRegex,proto3,oneof"`
}

func (*StringMatcher_Exact) isStringMatcher_MatchPattern() {}

func (*StringMatcher_Prefix) isStringMatcher_MatchPattern() {}

func (*StringMatcher_Suffix) isStringMatcher_MatchPattern() {}

func (*StringMatcher_Regex) isStringMatcher_MatchPattern() {}

func (*StringMatcher_SafeRegex) isStringMatcher_MatchPattern() {}

func (m *StringMatcher) GetMatchPattern() isStringMatcher_MatchPattern {
	if m != nil {
		return m.MatchPattern
	}
	return nil
}

func (m *StringMatcher) GetExact() string {
	if x, ok := m.GetMatchPattern().(*StringMatcher_Exact); ok {
		return x.Exact
	}
	return ""
}

func (m *StringMatcher) GetPrefix() string {
	if x, ok := m.GetMatchPattern().(*StringMatcher_Prefix); ok {
		return x.Prefix
	}
	return ""
}

func (m *StringMatcher) GetSuffix() string {
	if x, ok := m.GetMatchPattern().(*StringMatcher_Suffix); ok {
		return x.Suffix
	}
	return ""
}

// Deprecated: Do not use.
func (m *StringMatcher) GetRegex() string {
	if x, ok := m.GetMatchPattern().(*StringMatcher_Regex); ok {
		return x.Regex
	}
	return ""
}

func (m *StringMatcher) GetSafeRegex() *RegexMatcher {
	if x, ok := m.GetMatchPattern().(*StringMatcher_SafeRegex); ok {
		return x.SafeRegex
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*StringMatcher) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*StringMatcher_Exact)(nil),
		(*StringMatcher_Prefix)(nil),
		(*StringMatcher_Suffix)(nil),
		(*StringMatcher_Regex)(nil),
		(*StringMatcher_SafeRegex)(nil),
	}
}

// Specifies a list of ways to match a string.
type ListStringMatcher struct {
	Patterns             []*StringMatcher `protobuf:"bytes,1,rep,name=patterns,proto3" json:"patterns,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *ListStringMatcher) Reset()         { *m = ListStringMatcher{} }
func (m *ListStringMatcher) String() string { return proto.CompactTextString(m) }
func (*ListStringMatcher) ProtoMessage()    {}
func (*ListStringMatcher) Descriptor() ([]byte, []int) {
	return fileDescriptor_1dc62c75a0f154e3, []int{1}
}

func (m *ListStringMatcher) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListStringMatcher.Unmarshal(m, b)
}
func (m *ListStringMatcher) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListStringMatcher.Marshal(b, m, deterministic)
}
func (m *ListStringMatcher) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListStringMatcher.Merge(m, src)
}
func (m *ListStringMatcher) XXX_Size() int {
	return xxx_messageInfo_ListStringMatcher.Size(m)
}
func (m *ListStringMatcher) XXX_DiscardUnknown() {
	xxx_messageInfo_ListStringMatcher.DiscardUnknown(m)
}

var xxx_messageInfo_ListStringMatcher proto.InternalMessageInfo

func (m *ListStringMatcher) GetPatterns() []*StringMatcher {
	if m != nil {
		return m.Patterns
	}
	return nil
}

func init() {
	proto.RegisterType((*StringMatcher)(nil), "envoy.type.matcher.StringMatcher")
	proto.RegisterType((*ListStringMatcher)(nil), "envoy.type.matcher.ListStringMatcher")
}

func init() { proto.RegisterFile("envoy/type/matcher/string.proto", fileDescriptor_1dc62c75a0f154e3) }

var fileDescriptor_1dc62c75a0f154e3 = []byte{
	// 308 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x91, 0x31, 0x4b, 0xc3, 0x40,
	0x14, 0xc7, 0xfb, 0x92, 0xa6, 0xa6, 0xaf, 0x14, 0xf4, 0x10, 0x0d, 0x1d, 0xf4, 0xda, 0x29, 0x53,
	0x82, 0xf5, 0x1b, 0xdc, 0x62, 0x41, 0x85, 0x12, 0x57, 0xa1, 0x9c, 0xf5, 0x5a, 0x03, 0x9a, 0x84,
	0xcb, 0x59, 0x92, 0xcd, 0xd9, 0xd1, 0xcf, 0xea, 0x20, 0x99, 0xe4, 0xee, 0xa2, 0x50, 0x9a, 0x2d,
	0xe1, 0xff, 0xfb, 0xfd, 0xef, 0x3d, 0x1e, 0x5e, 0x8a, 0x6c, 0x97, 0xd7, 0xb1, 0xaa, 0x0b, 0x11,
	0xbf, 0x71, 0xb5, 0x7e, 0x11, 0x32, 0x2e, 0x95, 0x4c, 0xb3, 0x6d, 0x54, 0xc8, 0x5c, 0xe5, 0x84,
	0x18, 0x20, 0xd2, 0x40, 0xd4, 0x02, 0x93, 0x8b, 0x0e, 0x49, 0x8a, 0xad, 0xa8, 0xac, 0x33, 0x39,
	0xdf, 0xf1, 0xd7, 0xf4, 0x99, 0x2b, 0x11, 0xff, 0x7d, 0xd8, 0x60, 0xf6, 0x0d, 0x38, 0x7e, 0x30,
	0xed, 0xf7, 0x56, 0x23, 0x67, 0xe8, 0x89, 0x8a, 0xaf, 0x55, 0x00, 0x14, 0xc2, 0xe1, 0xa2, 0x97,
	0xd8, 0x5f, 0x32, 0xc5, 0x41, 0x21, 0xc5, 0x26, 0xad, 0x02, 0x47, 0x07, 0xec, 0xa8, 0x61, 0x7d,
	0xe9, 0x50, 0x58, 0xf4, 0x92, 0x36, 0xd0, 0x48, 0xf9, 0xbe, 0xd1, 0x88, 0x7b, 0x80, 0xd8, 0x80,
	0xcc, 0xd0, 0x33, 0x73, 0x05, 0x7d, 0x43, 0x60, 0xc3, 0x3c, 0xe9, 0x86, 0x1f, 0x7e, 0xa0, 0x21,
	0x1b, 0x91, 0x5b, 0xc4, 0x92, 0x6f, 0xc4, 0xca, 0x82, 0x1e, 0x85, 0x70, 0x34, 0xa7, 0xd1, 0xe1,
	0xd6, 0x51, 0xa2, 0x81, 0x76, 0x6e, 0xe6, 0x37, 0xcc, 0xfb, 0x04, 0xe7, 0x58, 0x17, 0x0d, 0xb5,
	0x6f, 0x52, 0x76, 0x8a, 0x63, 0x83, 0xaf, 0x0a, 0xae, 0x94, 0x90, 0x19, 0x71, 0x7f, 0x18, 0xcc,
	0x1e, 0xf1, 0xe4, 0x2e, 0x2d, 0xd5, 0xfe, 0xe6, 0x37, 0xe8, 0xb7, 0x50, 0x19, 0x00, 0x75, 0xc3,
	0xd1, 0x7c, 0xda, 0xf5, 0xea, 0x9e, 0x64, 0x9e, 0xfd, 0x02, 0xc7, 0x87, 0xe4, 0x5f, 0x66, 0x57,
	0x48, 0xd3, 0xdc, 0xaa, 0x85, 0xcc, 0xab, 0xba, 0xa3, 0x85, 0x8d, 0x6c, 0xcd, 0x52, 0x5f, 0x61,
	0x09, 0x4f, 0x03, 0x73, 0x8e, 0xeb, 0xdf, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x92, 0x4a, 0x0e,
	0xfe, 0x01, 0x00, 0x00,
}
