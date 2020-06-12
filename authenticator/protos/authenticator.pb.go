// Code generated by protoc-gen-go. DO NOT EDIT.
// source: authenticator.proto

package approzium_authenticator_protos

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
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

type PGMD5HashRequest struct {
	SignedGetCallerIdentity string   `protobuf:"bytes,1,opt,name=signed_get_caller_identity,json=signedGetCallerIdentity,proto3" json:"signed_get_caller_identity,omitempty"`
	ClaimedIamArn           string   `protobuf:"bytes,2,opt,name=claimed_iam_arn,json=claimedIamArn,proto3" json:"claimed_iam_arn,omitempty"`
	Dbhost                  string   `protobuf:"bytes,3,opt,name=dbhost,proto3" json:"dbhost,omitempty"`
	Dbuser                  string   `protobuf:"bytes,4,opt,name=dbuser,proto3" json:"dbuser,omitempty"`
	Salt                    []byte   `protobuf:"bytes,5,opt,name=salt,proto3" json:"salt,omitempty"`
	XXX_NoUnkeyedLiteral    struct{} `json:"-"`
	XXX_unrecognized        []byte   `json:"-"`
	XXX_sizecache           int32    `json:"-"`
}

func (m *PGMD5HashRequest) Reset()         { *m = PGMD5HashRequest{} }
func (m *PGMD5HashRequest) String() string { return proto.CompactTextString(m) }
func (*PGMD5HashRequest) ProtoMessage()    {}
func (*PGMD5HashRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_e86ec39f7c35dea3, []int{0}
}

func (m *PGMD5HashRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PGMD5HashRequest.Unmarshal(m, b)
}
func (m *PGMD5HashRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PGMD5HashRequest.Marshal(b, m, deterministic)
}
func (m *PGMD5HashRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PGMD5HashRequest.Merge(m, src)
}
func (m *PGMD5HashRequest) XXX_Size() int {
	return xxx_messageInfo_PGMD5HashRequest.Size(m)
}
func (m *PGMD5HashRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_PGMD5HashRequest.DiscardUnknown(m)
}

var xxx_messageInfo_PGMD5HashRequest proto.InternalMessageInfo

func (m *PGMD5HashRequest) GetSignedGetCallerIdentity() string {
	if m != nil {
		return m.SignedGetCallerIdentity
	}
	return ""
}

func (m *PGMD5HashRequest) GetClaimedIamArn() string {
	if m != nil {
		return m.ClaimedIamArn
	}
	return ""
}

func (m *PGMD5HashRequest) GetDbhost() string {
	if m != nil {
		return m.Dbhost
	}
	return ""
}

func (m *PGMD5HashRequest) GetDbuser() string {
	if m != nil {
		return m.Dbuser
	}
	return ""
}

func (m *PGMD5HashRequest) GetSalt() []byte {
	if m != nil {
		return m.Salt
	}
	return nil
}

type PGSHA256HashRequest struct {
	SignedGetCallerIdentity string   `protobuf:"bytes,1,opt,name=signed_get_caller_identity,json=signedGetCallerIdentity,proto3" json:"signed_get_caller_identity,omitempty"`
	ClaimedIamArn           string   `protobuf:"bytes,2,opt,name=claimed_iam_arn,json=claimedIamArn,proto3" json:"claimed_iam_arn,omitempty"`
	Dbhost                  string   `protobuf:"bytes,3,opt,name=dbhost,proto3" json:"dbhost,omitempty"`
	Dbuser                  string   `protobuf:"bytes,4,opt,name=dbuser,proto3" json:"dbuser,omitempty"`
	Salt                    []byte   `protobuf:"bytes,5,opt,name=salt,proto3" json:"salt,omitempty"`
	Iterations              uint32   `protobuf:"varint,6,opt,name=iterations,proto3" json:"iterations,omitempty"`
	XXX_NoUnkeyedLiteral    struct{} `json:"-"`
	XXX_unrecognized        []byte   `json:"-"`
	XXX_sizecache           int32    `json:"-"`
}

func (m *PGSHA256HashRequest) Reset()         { *m = PGSHA256HashRequest{} }
func (m *PGSHA256HashRequest) String() string { return proto.CompactTextString(m) }
func (*PGSHA256HashRequest) ProtoMessage()    {}
func (*PGSHA256HashRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_e86ec39f7c35dea3, []int{1}
}

func (m *PGSHA256HashRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PGSHA256HashRequest.Unmarshal(m, b)
}
func (m *PGSHA256HashRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PGSHA256HashRequest.Marshal(b, m, deterministic)
}
func (m *PGSHA256HashRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PGSHA256HashRequest.Merge(m, src)
}
func (m *PGSHA256HashRequest) XXX_Size() int {
	return xxx_messageInfo_PGSHA256HashRequest.Size(m)
}
func (m *PGSHA256HashRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_PGSHA256HashRequest.DiscardUnknown(m)
}

var xxx_messageInfo_PGSHA256HashRequest proto.InternalMessageInfo

func (m *PGSHA256HashRequest) GetSignedGetCallerIdentity() string {
	if m != nil {
		return m.SignedGetCallerIdentity
	}
	return ""
}

func (m *PGSHA256HashRequest) GetClaimedIamArn() string {
	if m != nil {
		return m.ClaimedIamArn
	}
	return ""
}

func (m *PGSHA256HashRequest) GetDbhost() string {
	if m != nil {
		return m.Dbhost
	}
	return ""
}

func (m *PGSHA256HashRequest) GetDbuser() string {
	if m != nil {
		return m.Dbuser
	}
	return ""
}

func (m *PGSHA256HashRequest) GetSalt() []byte {
	if m != nil {
		return m.Salt
	}
	return nil
}

func (m *PGSHA256HashRequest) GetIterations() uint32 {
	if m != nil {
		return m.Iterations
	}
	return 0
}

type PGMD5Response struct {
	Hash                 string   `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PGMD5Response) Reset()         { *m = PGMD5Response{} }
func (m *PGMD5Response) String() string { return proto.CompactTextString(m) }
func (*PGMD5Response) ProtoMessage()    {}
func (*PGMD5Response) Descriptor() ([]byte, []int) {
	return fileDescriptor_e86ec39f7c35dea3, []int{2}
}

func (m *PGMD5Response) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PGMD5Response.Unmarshal(m, b)
}
func (m *PGMD5Response) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PGMD5Response.Marshal(b, m, deterministic)
}
func (m *PGMD5Response) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PGMD5Response.Merge(m, src)
}
func (m *PGMD5Response) XXX_Size() int {
	return xxx_messageInfo_PGMD5Response.Size(m)
}
func (m *PGMD5Response) XXX_DiscardUnknown() {
	xxx_messageInfo_PGMD5Response.DiscardUnknown(m)
}

var xxx_messageInfo_PGMD5Response proto.InternalMessageInfo

func (m *PGMD5Response) GetHash() string {
	if m != nil {
		return m.Hash
	}
	return ""
}

type PGSHA256Response struct {
	Spassword            []byte   `protobuf:"bytes,1,opt,name=spassword,proto3" json:"spassword,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PGSHA256Response) Reset()         { *m = PGSHA256Response{} }
func (m *PGSHA256Response) String() string { return proto.CompactTextString(m) }
func (*PGSHA256Response) ProtoMessage()    {}
func (*PGSHA256Response) Descriptor() ([]byte, []int) {
	return fileDescriptor_e86ec39f7c35dea3, []int{3}
}

func (m *PGSHA256Response) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PGSHA256Response.Unmarshal(m, b)
}
func (m *PGSHA256Response) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PGSHA256Response.Marshal(b, m, deterministic)
}
func (m *PGSHA256Response) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PGSHA256Response.Merge(m, src)
}
func (m *PGSHA256Response) XXX_Size() int {
	return xxx_messageInfo_PGSHA256Response.Size(m)
}
func (m *PGSHA256Response) XXX_DiscardUnknown() {
	xxx_messageInfo_PGSHA256Response.DiscardUnknown(m)
}

var xxx_messageInfo_PGSHA256Response proto.InternalMessageInfo

func (m *PGSHA256Response) GetSpassword() []byte {
	if m != nil {
		return m.Spassword
	}
	return nil
}

func init() {
	proto.RegisterType((*PGMD5HashRequest)(nil), "approzium.authenticator.protos.PGMD5HashRequest")
	proto.RegisterType((*PGSHA256HashRequest)(nil), "approzium.authenticator.protos.PGSHA256HashRequest")
	proto.RegisterType((*PGMD5Response)(nil), "approzium.authenticator.protos.PGMD5Response")
	proto.RegisterType((*PGSHA256Response)(nil), "approzium.authenticator.protos.PGSHA256Response")
}

func init() { proto.RegisterFile("authenticator.proto", fileDescriptor_e86ec39f7c35dea3) }

var fileDescriptor_e86ec39f7c35dea3 = []byte{
	// 344 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xd4, 0x52, 0x41, 0x6b, 0xf2, 0x40,
	0x10, 0xfd, 0xf6, 0xab, 0x15, 0x1c, 0x0c, 0x96, 0x15, 0xda, 0x20, 0x45, 0x24, 0x85, 0xe2, 0xa5,
	0x41, 0x14, 0x7b, 0xe9, 0x49, 0x5a, 0x88, 0x1e, 0x0a, 0x92, 0xfe, 0x80, 0xb0, 0x9a, 0xc5, 0x2c,
	0x24, 0xd9, 0xb8, 0xb3, 0xa1, 0xd4, 0xbf, 0xd6, 0xff, 0xd2, 0x9f, 0x52, 0x4a, 0xd6, 0x68, 0xa4,
	0x2d, 0xad, 0xd7, 0xde, 0x76, 0xde, 0x9b, 0x37, 0x93, 0xc9, 0x7b, 0xd0, 0x66, 0xb9, 0x8e, 0x78,
	0xaa, 0xc5, 0x92, 0x69, 0xa9, 0xdc, 0x4c, 0x49, 0x2d, 0x69, 0x97, 0x65, 0x99, 0x92, 0x1b, 0x91,
	0x27, 0xee, 0x37, 0x34, 0x3a, 0xaf, 0x04, 0xce, 0xe6, 0xde, 0xe3, 0xc3, 0x78, 0xca, 0x30, 0xf2,
	0xf9, 0x3a, 0xe7, 0xa8, 0xe9, 0x1d, 0x74, 0x50, 0xac, 0x52, 0x1e, 0x06, 0x2b, 0xae, 0x83, 0x25,
	0x8b, 0x63, 0xae, 0x02, 0x11, 0x16, 0x62, 0xfd, 0x62, 0x93, 0x1e, 0xe9, 0x37, 0xfc, 0x8b, 0x6d,
	0x87, 0xc7, 0xf5, 0xbd, 0xe1, 0x67, 0x25, 0x4d, 0xaf, 0xa1, 0xb5, 0x8c, 0x99, 0x48, 0x78, 0x18,
	0x08, 0x96, 0x04, 0x4c, 0xa5, 0xf6, 0x7f, 0xa3, 0xb0, 0x4a, 0x78, 0xc6, 0x92, 0x89, 0x4a, 0xe9,
	0x39, 0xd4, 0xc3, 0x45, 0x24, 0x51, 0xdb, 0x27, 0x86, 0x2e, 0xab, 0x2d, 0x9e, 0x23, 0x57, 0x76,
	0x6d, 0x87, 0x17, 0x15, 0xa5, 0x50, 0x43, 0x16, 0x6b, 0xfb, 0xb4, 0x47, 0xfa, 0x4d, 0xdf, 0xbc,
	0x9d, 0x37, 0x02, 0xed, 0xb9, 0xf7, 0x34, 0x9d, 0x0c, 0xc7, 0xb7, 0x7f, 0xf1, 0x00, 0xda, 0x05,
	0x10, 0x9a, 0x2b, 0xa6, 0x85, 0x4c, 0xd1, 0xae, 0xf7, 0x48, 0xdf, 0xf2, 0x0f, 0x10, 0xe7, 0x0a,
	0x2c, 0xe3, 0x8e, 0xcf, 0x31, 0x93, 0x29, 0xf2, 0x62, 0x48, 0xc4, 0x30, 0x2a, 0x6f, 0x30, 0x6f,
	0x67, 0x50, 0x58, 0xb8, 0xfd, 0x09, 0xfb, 0xbe, 0x4b, 0x68, 0x60, 0xc6, 0x10, 0x9f, 0xa5, 0x0a,
	0x4d, 0x73, 0xd3, 0xaf, 0x80, 0xe1, 0x3b, 0x01, 0x6b, 0x72, 0x18, 0x07, 0xba, 0x86, 0xa6, 0xc7,
	0xf5, 0x3e, 0x09, 0x74, 0xe0, 0xfe, 0x1c, 0x1c, 0xf7, 0x73, 0x68, 0x3a, 0x37, 0x47, 0x29, 0x76,
	0x1f, 0xe8, 0xfc, 0xa3, 0x1b, 0x68, 0x99, 0x95, 0x95, 0x7d, 0x74, 0xf4, 0xfb, 0x8c, 0x2f, 0x66,
	0x77, 0x06, 0xc7, 0x8a, 0xaa, 0xdd, 0x8b, 0xba, 0xa1, 0x46, 0x1f, 0x01, 0x00, 0x00, 0xff, 0xff,
	0xc0, 0xe8, 0x82, 0x62, 0x34, 0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// AuthenticatorClient is the client API for Authenticator service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AuthenticatorClient interface {
	GetPGMD5Hash(ctx context.Context, in *PGMD5HashRequest, opts ...grpc.CallOption) (*PGMD5Response, error)
	GetPGSHA256Hash(ctx context.Context, in *PGSHA256HashRequest, opts ...grpc.CallOption) (*PGSHA256Response, error)
}

type authenticatorClient struct {
	cc *grpc.ClientConn
}

func NewAuthenticatorClient(cc *grpc.ClientConn) AuthenticatorClient {
	return &authenticatorClient{cc}
}

func (c *authenticatorClient) GetPGMD5Hash(ctx context.Context, in *PGMD5HashRequest, opts ...grpc.CallOption) (*PGMD5Response, error) {
	out := new(PGMD5Response)
	err := c.cc.Invoke(ctx, "/approzium.authenticator.protos.Authenticator/GetPGMD5Hash", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticatorClient) GetPGSHA256Hash(ctx context.Context, in *PGSHA256HashRequest, opts ...grpc.CallOption) (*PGSHA256Response, error) {
	out := new(PGSHA256Response)
	err := c.cc.Invoke(ctx, "/approzium.authenticator.protos.Authenticator/GetPGSHA256Hash", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthenticatorServer is the server API for Authenticator service.
type AuthenticatorServer interface {
	GetPGMD5Hash(context.Context, *PGMD5HashRequest) (*PGMD5Response, error)
	GetPGSHA256Hash(context.Context, *PGSHA256HashRequest) (*PGSHA256Response, error)
}

// UnimplementedAuthenticatorServer can be embedded to have forward compatible implementations.
type UnimplementedAuthenticatorServer struct {
}

func (*UnimplementedAuthenticatorServer) GetPGMD5Hash(ctx context.Context, req *PGMD5HashRequest) (*PGMD5Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPGMD5Hash not implemented")
}
func (*UnimplementedAuthenticatorServer) GetPGSHA256Hash(ctx context.Context, req *PGSHA256HashRequest) (*PGSHA256Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPGSHA256Hash not implemented")
}

func RegisterAuthenticatorServer(s *grpc.Server, srv AuthenticatorServer) {
	s.RegisterService(&_Authenticator_serviceDesc, srv)
}

func _Authenticator_GetPGMD5Hash_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PGMD5HashRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticatorServer).GetPGMD5Hash(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/approzium.authenticator.protos.Authenticator/GetPGMD5Hash",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticatorServer).GetPGMD5Hash(ctx, req.(*PGMD5HashRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Authenticator_GetPGSHA256Hash_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PGSHA256HashRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticatorServer).GetPGSHA256Hash(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/approzium.authenticator.protos.Authenticator/GetPGSHA256Hash",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticatorServer).GetPGSHA256Hash(ctx, req.(*PGSHA256HashRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Authenticator_serviceDesc = grpc.ServiceDesc{
	ServiceName: "approzium.authenticator.protos.Authenticator",
	HandlerType: (*AuthenticatorServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetPGMD5Hash",
			Handler:    _Authenticator_GetPGMD5Hash_Handler,
		},
		{
			MethodName: "GetPGSHA256Hash",
			Handler:    _Authenticator_GetPGSHA256Hash_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "authenticator.proto",
}
