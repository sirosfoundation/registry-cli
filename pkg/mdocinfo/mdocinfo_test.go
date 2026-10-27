package mdocinfo

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    Info
		wantErr bool
	}{
		{"top-level docType", `{"title":" T ","description":"D","docType":"x.y.1"}`, Info{"T", "D", "x.y.1"}, false},
		{"properties const", `{"title":"T","properties":{"docType":{"type":"string","const":"eu.pid.1"}}}`, Info{Title: "T", DocType: "eu.pid.1"}, false},
		{"nested in defs", `{"$defs":{"issuance":{"properties":{"docType":{"const":"eu.ecmr.v1"}}}}}`, Info{DocType: "eu.ecmr.v1"}, false},
		{"nested in oneOf", `{"oneOf":[{"properties":{"docType":{"const":"a.b"}}}]}`, Info{DocType: "a.b"}, false},
		{"none", `{"title":"only title"}`, Info{Title: "only title"}, false},
		{"not json", `{nope`, Info{}, true},
		{"null", `null`, Info{}, true},
		{"array", `[]`, Info{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse([]byte(tt.in))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
