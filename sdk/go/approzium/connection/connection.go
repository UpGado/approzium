package connection

import (
	"context"

	pb "github.com/cyralinc/approzium/authenticator/server/protos"
	"google.golang.org/grpc"
)

func NewHandler(grpcAddress string) pb.AuthenticatorClient {
	return &Handler{
		grpcAddress: grpcAddress,
	}
}

type Handler struct {
	grpcAddress string
}

func (a *Handler) GetPGMD5Hash(ctx context.Context, in *pb.PGMD5HashRequest, opts ...grpc.CallOption) (*pb.PGMD5Response, error) {
	// TODO
	return nil, nil
}

func (a *Handler) GetPGSHA256Hash(ctx context.Context, in *pb.PGSHA256HashRequest, opts ...grpc.CallOption) (*pb.PGSHA256Response, error) {
	// TODO
	return nil, nil
}

func (a *Handler) GetMYSQLSHA1Hash(ctx context.Context, in *pb.MYSQLSHA1HashRequest, opts ...grpc.CallOption) (*pb.MYSQLSHA1Response, error) {
	// TODO
	return nil, nil
}

func (a *Handler) stubbedClient() (pb.AuthenticatorClient, func() error, error) {
	conn, err := grpc.Dial(a.grpcAddress, grpc.WithInsecure())
	if err != nil {
		return nil, nil, err
	}
	return pb.NewAuthenticatorClient(conn), conn.Close, nil
}
