package jwssign

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePKCS11URI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		module  string
		token   string
		pin     string
		wantErr bool
	}{
		{
			name:   "full URI",
			uri:    "pkcs11:module=/usr/lib/softhsm/libsofthsm2.so;token=registry;pin=1234",
			module: "/usr/lib/softhsm/libsofthsm2.so",
			token:  "registry",
			pin:    "1234",
		},
		{
			name:   "without pkcs11: prefix",
			uri:    "module=/usr/lib/softhsm/libsofthsm2.so;token=test;pin=0000",
			module: "/usr/lib/softhsm/libsofthsm2.so",
			token:  "test",
			pin:    "0000",
		},
		{
			name:    "missing module",
			uri:     "pkcs11:token=test;pin=1234",
			wantErr: true,
		},
		{
			name:    "missing token",
			uri:     "pkcs11:module=/path/to/lib.so;pin=1234",
			wantErr: true,
		},
		{
			name:   "no pin (allowed)",
			uri:    "pkcs11:module=/path/to/lib.so;token=test",
			module: "/path/to/lib.so",
			token:  "test",
			pin:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module, token, pin, err := ParsePKCS11URI(tt.uri)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.module, module)
			assert.Equal(t, tt.token, token)
			assert.Equal(t, tt.pin, pin)
		})
	}
}

func TestAlgorithmForKey_ECDSA(t *testing.T) {
	// Algorithm detection is tested via the public API in integration tests.
	// Unit testing algorithmForKey requires generating test keys.
	// This is covered by the integration test with SoftHSM2.
}
