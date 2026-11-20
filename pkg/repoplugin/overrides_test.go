package repoplugin

import "testing"

func TestDisclosureOverrideFor(t *testing.T) {
	tests := []struct {
		name     string
		override *DisclosureOverride
		path     []string
		want     string
		wantOK   bool
	}{
		{
			name:   "a nil override never applies",
			path:   []string{"id"},
			wantOK: false,
		},
		{
			// EBWOID: rb-ebwoid sections 4.5 and 5.1 forbid selective
			// disclosure of any attribute.
			name:     "default covers every claim",
			override: &DisclosureOverride{Default: "never"},
			path:     []string{"issuing_authority"},
			want:     "never",
			wantOK:   true,
		},
		{
			name:     "default reaches nested claims too",
			override: &DisclosureOverride{Default: "never"},
			path:     []string{"administrative_unit", "vat_id"},
			want:     "never",
			wantOK:   true,
		},
		{
			name: "a claim entry beats the default",
			override: &DisclosureOverride{
				Default: "never",
				Claims:  map[string]string{"receipt_number": "always"},
			},
			path:   []string{"receipt_number"},
			want:   "always",
			wantOK: true,
		},
		{
			name: "a nested claim is addressed by dotted path",
			override: &DisclosureOverride{
				Claims: map[string]string{"merchant.name": "always"},
			},
			path:   []string{"merchant", "name"},
			want:   "always",
			wantOK: true,
		},
		{
			name: "an unlisted claim falls through when there is no default",
			override: &DisclosureOverride{
				Claims: map[string]string{"receipt_number": "always"},
			},
			path:   []string{"total_vat_amount"},
			wantOK: false,
		},
		{
			name: "the dotted path does not match a different nesting",
			override: &DisclosureOverride{
				Claims: map[string]string{"merchant.name": "always"},
			},
			path:   []string{"name"},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.override.For(tt.path)
			if ok != tt.wantOK {
				t.Fatalf("applied = %v, want %v", ok, tt.wantOK)
			}

			if got != tt.want {
				t.Errorf("sd = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDisclosureOverrideValidate(t *testing.T) {
	tests := []struct {
		name     string
		override *DisclosureOverride
		wantErr  bool
	}{
		{name: "nil is fine", override: nil},
		{name: "never", override: &DisclosureOverride{Default: "never"}},
		{name: "always", override: &DisclosureOverride{Default: "always"}},
		{name: "allowed", override: &DisclosureOverride{Default: "allowed"}},
		{
			name:     "per-claim values are checked too",
			override: &DisclosureOverride{Claims: map[string]string{"id": "never"}},
		},
		{
			// Without this, a typo would be published to wallets as a
			// claim-level instruction.
			name:     "an unknown default is rejected",
			override: &DisclosureOverride{Default: "atomic"},
			wantErr:  true,
		},
		{
			name:     "an unknown claim value is rejected",
			override: &DisclosureOverride{Claims: map[string]string{"id": "Never"}},
			wantErr:  true,
		},
		{
			name:     "an empty override is rejected as a likely mistake",
			override: &DisclosureOverride{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.override.Validate("ebwoid")
			if tt.wantErr && err == nil {
				t.Fatal("expected an error, got none")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantErr && err != nil {
				t.Logf("rejected with: %v", err)
			}
		})
	}
}
