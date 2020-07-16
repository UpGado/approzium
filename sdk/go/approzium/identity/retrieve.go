package identity

import pb "github.com/cyralinc/approzium/authenticator/server/protos"

type Identity struct {
	AWS *pb.AWSIdentity
}

func Retrieve() (*Identity, error) {
	// TODO
	return nil, nil
}
