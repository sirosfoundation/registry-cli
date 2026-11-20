package repoplugin

import (
	"fmt"
	"sort"
	"strings"
)

// DisclosureValues are the selective-disclosure values SD-JWT VC defines for a
// claim, in section 9.3 of draft-ietf-oauth-sd-jwt-vc. An absent value means
// "allowed".
var DisclosureValues = []string{"always", "allowed", "never"}

// CredentialOverride carries per-credential settings declared in sources.yaml.
// It exists for facts a publisher knows that the published repository does not
// state in a machine-readable way.
type CredentialOverride struct {
	Disclosure *DisclosureOverride `yaml:"disclosure,omitempty"`
}

// DisclosureOverride states a selective-disclosure policy for a credential.
//
// Some rulebooks place that policy normatively in the rulebook prose rather
// than in the schema a generator can read. EBWOID is the case this was written
// for: rb-ebwoid sections 4.5 and 5.1 require the attestation to be presented
// atomically, with no attribute selectively disclosable, but its JSON Schema
// says nothing about disclosure, so a generated VCTM leaves `sd` unset and the
// claim defaults to "allowed" — the opposite of the rulebook.
//
//	credentials:
//	  ebwoid:
//	    disclosure:
//	      default: never
//	  e-receipt:
//	    disclosure:
//	      claims:
//	        receipt_number: never
//	        merchant.name: always
//
// Claims are addressed by their path joined with ".", so a nested claim is
// "parent.child". A claim entry wins over `default`, and both win over
// anything inferred from the schema.
type DisclosureOverride struct {
	// Default applies to every claim of the credential.
	Default string `yaml:"default,omitempty"`

	// Claims applies to one claim each, by dotted path.
	Claims map[string]string `yaml:"claims,omitempty"`
}

// For returns the disclosure value that applies to a claim path, and whether
// any override applied at all. A nil override never applies, so callers can
// fall back to whatever they would otherwise infer.
func (d *DisclosureOverride) For(path []string) (string, bool) {
	if d == nil {
		return "", false
	}

	if sd, ok := d.Claims[strings.Join(path, ".")]; ok {
		return sd, true
	}

	if d.Default != "" {
		return d.Default, true
	}

	return "", false
}

// Validate reports whether every value in the override is one SD-JWT VC
// defines. A typo here would otherwise be published as a claim-level
// instruction to wallets, so it is rejected when the manifest loads rather
// than carried into the output.
func (d *DisclosureOverride) Validate(credential string) error {
	if d == nil {
		return nil
	}

	if err := validDisclosure(d.Default); err != nil {
		return fmt.Errorf("credential %q: disclosure.default: %w", credential, err)
	}

	claims := make([]string, 0, len(d.Claims))
	for claim := range d.Claims {
		claims = append(claims, claim)
	}
	sort.Strings(claims)

	for _, claim := range claims {
		if err := validDisclosure(d.Claims[claim]); err != nil {
			return fmt.Errorf("credential %q: disclosure.claims.%s: %w", credential, claim, err)
		}
	}

	if d.Default == "" && len(d.Claims) == 0 {
		return fmt.Errorf("credential %q: disclosure is empty; set default or claims", credential)
	}

	return nil
}

func validDisclosure(value string) error {
	if value == "" {
		return nil
	}

	for _, allowed := range DisclosureValues {
		if value == allowed {
			return nil
		}
	}

	return fmt.Errorf("%q is not one of %s", value, strings.Join(DisclosureValues, ", "))
}
