package identity

import (
	"github.com/cyralinc/approzium/authenticator/server/identity"
	pb "github.com/cyralinc/approzium/authenticator/server/protos"
)

func NewHandler(roleArnToAssume string) (*Handler, error) {
	awsHandler, err := newAwsIdentityHandler(roleArnToAssume)
	if err != nil {
		return nil, err
	}
	return &Handler{
		awsIdentityHandler: awsHandler,
	}, nil
}

type Handler struct {
	awsIdentityHandler *awsIdentityHandler
}

// Retrieve gets current identity info. The returned identity
// SHOULD NOT be cached or reused, because it expires every 15
// minutes or less.
func (h *Handler) Retrieve() *identity.Proof {
	return &identity.Proof{
		ClientLang: pb.ClientLanguage_GO,
		AwsAuth:    h.awsIdentityHandler.RetrieveAWSIdentity(),
	}
}