// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package switchrpc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// SwitchClient is the client API for Switch service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SwitchClient interface {
	// SendOnion attempts to make a payment via the specified onion. This
	// method differs from SendPayment in that the instance need not be aware of
	// the full details of the payment route.
	SendOnion(ctx context.Context, in *SendOnionRequest, opts ...grpc.CallOption) (*SendOnionResponse, error)
}

type switchClient struct {
	cc grpc.ClientConnInterface
}

func NewSwitchClient(cc grpc.ClientConnInterface) SwitchClient {
	return &switchClient{cc}
}

func (c *switchClient) SendOnion(ctx context.Context, in *SendOnionRequest, opts ...grpc.CallOption) (*SendOnionResponse, error) {
	out := new(SendOnionResponse)
	err := c.cc.Invoke(ctx, "/switchrpc.Switch/SendOnion", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SwitchServer is the server API for Switch service.
// All implementations must embed UnimplementedSwitchServer
// for forward compatibility
type SwitchServer interface {
	// SendOnion attempts to make a payment via the specified onion. This
	// method differs from SendPayment in that the instance need not be aware of
	// the full details of the payment route.
	SendOnion(context.Context, *SendOnionRequest) (*SendOnionResponse, error)
	mustEmbedUnimplementedSwitchServer()
}

// UnimplementedSwitchServer must be embedded to have forward compatible implementations.
type UnimplementedSwitchServer struct {
}

func (UnimplementedSwitchServer) SendOnion(context.Context, *SendOnionRequest) (*SendOnionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendOnion not implemented")
}
func (UnimplementedSwitchServer) mustEmbedUnimplementedSwitchServer() {}

// UnsafeSwitchServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SwitchServer will
// result in compilation errors.
type UnsafeSwitchServer interface {
	mustEmbedUnimplementedSwitchServer()
}

func RegisterSwitchServer(s grpc.ServiceRegistrar, srv SwitchServer) {
	s.RegisterService(&Switch_ServiceDesc, srv)
}

func _Switch_SendOnion_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SendOnionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SwitchServer).SendOnion(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/switchrpc.Switch/SendOnion",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SwitchServer).SendOnion(ctx, req.(*SendOnionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Switch_ServiceDesc is the grpc.ServiceDesc for Switch service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Switch_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "switchrpc.Switch",
	HandlerType: (*SwitchServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SendOnion",
			Handler:    _Switch_SendOnion_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "switchrpc/switch.proto",
}
