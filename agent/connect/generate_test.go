package connect

import (
	"fmt"
	"testing"
	"time"

	"crypto/x509"
	"encoding/pem"

	"github.com/hashicorp/consul/agent/structs"
	"github.com/stretchr/testify/require"
)

type KeyConfig struct {
	keyType string
	keyBits int
}

var goodParams, badParams []KeyConfig

func init() {
	goodParams = []KeyConfig{
		{keyType: "rsa", keyBits: 2048},
		{keyType: "rsa", keyBits: 4096},
		{keyType: "ecdsa", keyBits: 224},
		{keyType: "ecdsa", keyBits: 256},
		{keyType: "ecdsa", keyBits: 384},
		{keyType: "ecdsa", keyBits: 521},
	}
	badParams = []KeyConfig{
		{keyType: "rsa", keyBits: 0},
		{keyType: "rsa", keyBits: 1024},
		{keyType: "ecdsa", keyBits: 0},
		{keyType: "ecdsa", keyBits: 512},
		{keyType: "aes", keyBits: 128},
	}
}

func makeConfig(kc KeyConfig) structs.CommonCAProviderConfig {
	return structs.CommonCAProviderConfig{
		LeafCertTTL:    3 * 24 * time.Hour,
		PrivateKeyType: kc.keyType,
		PrivateKeyBits: kc.keyBits,
	}
}

func testGenerateRSAKey(t *testing.T, bits int) {
	r := require.New(t)
	_, rsaBlock, err := GeneratePrivateKeyWithConfig("rsa", bits)
	r.NoError(err)
	r.Contains(rsaBlock, "RSA PRIVATE KEY")

	rsaBytes, _ := pem.Decode([]byte(rsaBlock))
	r.NotNil(rsaBytes)

	rsaKey, err := x509.ParsePKCS1PrivateKey(rsaBytes.Bytes)
	r.NoError(err)
	r.NoError(rsaKey.Validate())
	r.Equal(bits/8, rsaKey.Size()) // note: returned size is in bytes. 2048/8==256
}

func testGenerateECDSAKey(t *testing.T, bits int) {
	r := require.New(t)
	_, pemBlock, err := GeneratePrivateKeyWithConfig("ecdsa", bits)
	r.NoError(err)
	r.Contains(pemBlock, "EC PRIVATE KEY")

	block, _ := pem.Decode([]byte(pemBlock))
	r.NotNil(block)

	pk, err := x509.ParseECPrivateKey(block.Bytes)
	r.NoError(err)
	r.Equal(bits, pk.Curve.Params().BitSize)
}

func TestGenerateKeys(t *testing.T) {
	t.Parallel()
	for _, params := range goodParams {
		t.Run(fmt.Sprintf("TestGenerateKeys-%s-%d", params.keyType, params.keyBits),
			func(t *testing.T) {
				switch params.keyType {
				case "rsa":
					testGenerateRSAKey(t, params.keyBits)
				case "ecdsa":
					testGenerateECDSAKey(t, params.keyBits)
				default:
					t.Fatalf("unkown key type: %s", params.keyType)
				}
			})
	}
}

func TestValidateGoodConfigs(t *testing.T) {
	t.Parallel()
	for _, params := range goodParams {
		config := makeConfig(params)
		t.Run(fmt.Sprintf("TestValidateGoodConfigs-%s-%d", params.keyType, params.keyBits),
			func(t *testing.T) {
				require.New(t).NoError(config.Validate(), "unexpected error: type=%s bits=%d",
					params.keyType, params.keyBits)
			})

	}
}

func TestValidateBadConfigs(t *testing.T) {
	t.Parallel()
	for _, params := range badParams {
		config := makeConfig(params)
		t.Run(fmt.Sprintf("TestValidateBadConfigs-%s-%d", params.keyType, params.keyBits), func(t *testing.T) {
			require.New(t).Error(config.Validate(), "expected error: type=%s bits=%d",
				params.keyType, params.keyBits)
		})
	}
}
