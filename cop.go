package jose

import (
	"errors"
	"fmt"
)

// VerifyCOP works exactly like Verify but supports OpenBanking crit claims used by CoP
func (obj JSONWebSignature) VerifyCOP(verificationKey interface{}) ([]byte, error) {
	err := obj.DetachedVerifyCOP(obj.payload, verificationKey)
	if err != nil {
		return nil, err
	}
	return obj.payload, nil
}

// DetachedVerifyCOP works exactly like DetachedVerify but supports OpenBanking crit claims used by CoP
func (obj JSONWebSignature) DetachedVerifyCOP(payload []byte, verificationKey interface{}) error {
	key := tryJWKS(verificationKey, obj.headers()...)
	verifier, err := newVerifier(key)
	if err != nil {
		return err
	}

	if len(obj.Signatures) > 1 {
		return errors.New("go-jose/go-jose: too many signatures in payload; expecting only one")
	}

	signature := obj.Signatures[0]
	headers := signature.mergedHeaders()
	critical, err := headers.getCritical()
	if err != nil {
		return err
	}

	for _, name := range critical {
		if !supportedCriticalCOP[name] {
			return fmt.Errorf("Unsupported crit value")
		}
	}

	input, err := obj.computeAuthData(payload, &signature)
	if err != nil {
		return fmt.Errorf("unable to compute auth data: %v", err)
	}

	alg := headers.getSignatureAlgorithm()
	err = verifier.verifyPayload(input, signature.Signature, alg)
	if err == nil {
		return nil
	}

	return fmt.Errorf("unable to verify signature: %v", err)
}

var supportedCriticalCOP = map[string]bool{
	headerB64:                            true,
	"http://payments-services.co.uk/iat": true,
	"http://payments-services.co.uk/iss": true,
	"http://payments-services.co.uk/tan": true,
	"http://openbanking.org.uk/iat":      true,
	"http://openbanking.org.uk/iss":      true,
	"http://openbanking.org.uk/tan":      true,
}
