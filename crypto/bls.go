package crypto

import (
	"io"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
	"go.dedis.ch/kyber/v4/sign/bls"
	"go.dedis.ch/kyber/v4/util/random"
)

type (
	BLSPub struct {
		kyber.Point
	}

	BLSPriv struct {
		kyber.Scalar
	}
)

var kyberSuite = pairing.NewSuiteBn256()

func NewBLSPrivateKey(priv kyber.Scalar) PrivateKey {
	if priv == nil {
		return nil
	}

	return BLSPriv{Scalar: priv}
}

func NewBLSPublicKey(pub kyber.Point) PublicKey {
	if pub == nil {
		return nil
	}

	return BLSPub{Point: pub}
}

func generateBLS(r io.Reader) (PrivateKey, PublicKey) {
	priv, pub := bls.NewKeyPair(kyberSuite, random.New(r))
	return NewBLSPrivateKey(priv), NewBLSPublicKey(pub)
}

func (b BLSPub) Verify(msg, sig []byte) error {
	return bls.Verify(kyberSuite, b.Point, msg, sig)
}

func (b BLSPriv) Sign(msg []byte) ([]byte, error) {
	return bls.Sign(kyberSuite, b.Scalar, msg)
}

func AggregateBLSSignatures(sigs ...[]byte) ([]byte, error) {
	return bls.AggregateSignatures(kyberSuite, sigs...)
}

func AggregateBLSPublicKeys(pubs ...PublicKey) PublicKey {
	keys := make([]kyber.Point, len(pubs))
	for i := range keys {
		keys[i] = pubs[i].(BLSPub).Point
	}
	return NewBLSPublicKey(bls.AggregatePublicKeys(kyberSuite, keys...))
}
