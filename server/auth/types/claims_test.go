package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestUnmarshalJSON(t *testing.T) {
	testExpiry := jwt.NumericDate(1626527469)
	testissuedAt := jwt.NumericDate(1626467469)

	tests := []struct {
		description     string
		data            string
		customClaimName string
		expectedClaims  *Claims
		expectedErr     error
	}{
		{
			description:     "unmarshal valid data",
			data:            `{"user_tz":"America\/Chicago","sub":"test-user@argoproj.github.io","user_locale":"en","idp_name":"UserNamePassword","user.tenant.name":"test-user","onBehalfOfUser":true,"idp_guid":"UserNamePassword","amr":["USERNAME_PASSWORD"],"iss":"https:\/\/identity-service.argoproj.github.io","user_tenantname":"test-user","client_id":"tokenGenerator","user_isAdmin":true,"sub_type":"user","scope":"","client_tenantname":"argo-proj","region_name":"us1","user_lang":"en","userAppRoles":["Authenticated","Global Viewer","Identity Domain Administrator"],"exp":1626527469,"iat":1626467469,"client_guid":"adsf34534645654653454","client_name":"tokenGenerator","idp_type":"LOCAL","tenant":"test-user23523423","jti":"345sd435d454356","ad_groups":["argo_admin", "argo_readonly"],"gtp":"jwt","user_displayname":"Test User","sub_mappingattr":"userName","primTenant":true,"tok_type":"AT","ca_guid":"test-ca_guid","aud":["example-aud"],"user_id":"8948923893458945234","clientAppRoles":["Authenticated Client","Cross Tenant"],"tenant_iss":"https:\/\/identiy-service.argoproj.github.io"}`,
			customClaimName: "ad_groups",
			expectedErr:     nil,
			expectedClaims: &Claims{
				Claims: jwt.Claims{
					ID:        "345sd435d454356",
					Audience:  jwt.Audience{"example-aud"},
					Issuer:    "https://identity-service.argoproj.github.io",
					Subject:   "test-user@argoproj.github.io",
					Expiry:    &testExpiry,
					NotBefore: nil,
					IssuedAt:  &testissuedAt,
				},
				Groups:             []string{"argo_admin", "argo_readonly"},
				ServiceAccountName: "",
			},
		},
		{
			description: "unmarshal valid data, with default custom groups name",
			data:        `{"user_tz":"America\/Chicago","sub":"test-user@argoproj.github.io","user_locale":"en","idp_name":"UserNamePassword","user.tenant.name":"test-user","onBehalfOfUser":true,"idp_guid":"UserNamePassword","amr":["USERNAME_PASSWORD"],"iss":"https:\/\/identity-service.argoproj.github.io","user_tenantname":"test-user","client_id":"tokenGenerator","user_isAdmin":true,"sub_type":"user","scope":"","client_tenantname":"argo-proj","region_name":"us1","user_lang":"en","userAppRoles":["Authenticated","Global Viewer","Identity Domain Administrator"],"exp":1626527469,"iat":1626467469,"client_guid":"adsf34534645654653454","client_name":"tokenGenerator","idp_type":"LOCAL","tenant":"test-user23523423","jti":"345sd435d454356","groups":["argo_admin", "argo_readonly"],"gtp":"jwt","user_displayname":"Test User","sub_mappingattr":"userName","primTenant":true,"tok_type":"AT","ca_guid":"test-ca_guid","aud":["example-aud"],"user_id":"8948923893458945234","clientAppRoles":["Authenticated Client","Cross Tenant"],"tenant_iss":"https:\/\/identiy-service.argoproj.github.io"}`,
			expectedErr: nil,
			expectedClaims: &Claims{
				Claims: jwt.Claims{
					ID:        "345sd435d454356",
					Audience:  jwt.Audience{"example-aud"},
					Issuer:    "https://identity-service.argoproj.github.io",
					Subject:   "test-user@argoproj.github.io",
					Expiry:    &testExpiry,
					NotBefore: nil,
					IssuedAt:  &testissuedAt,
				},
				Groups:             []string{"argo_admin", "argo_readonly"},
				ServiceAccountName: "",
			},
		},
		{
			description: "unmarshal with incorrect custom groups name so no groups data is loaded",
			data:        `{"user_tz":"America\/Chicago","sub":"test-user@argoproj.github.io","user_locale":"en","idp_name":"UserNamePassword","user.tenant.name":"test-user","onBehalfOfUser":true,"idp_guid":"UserNamePassword","amr":["USERNAME_PASSWORD"],"iss":"https:\/\/identity-service.argoproj.github.io","user_tenantname":"test-user","client_id":"tokenGenerator","user_isAdmin":true,"sub_type":"user","scope":"","client_tenantname":"argo-proj","region_name":"us1","user_lang":"en","userAppRoles":["Authenticated","Global Viewer","Identity Domain Administrator"],"exp":1626527469,"iat":1626467469,"client_guid":"adsf34534645654653454","client_name":"tokenGenerator","idp_type":"LOCAL","tenant":"test-user23523423","jti":"345sd435d454356","ad_groups":["argo_admin", "argo_readonly"],"gtp":"jwt","user_displayname":"Test User","sub_mappingattr":"userName","primTenant":true,"tok_type":"AT","ca_guid":"test-ca_guid","aud":["example-aud"],"user_id":"8948923893458945234","clientAppRoles":["Authenticated Client","Cross Tenant"],"tenant_iss":"https:\/\/identiy-service.argoproj.github.io"}`,
			expectedErr: nil,
			expectedClaims: &Claims{
				Claims: jwt.Claims{
					ID:        "345sd435d454356",
					Audience:  jwt.Audience{"example-aud"},
					Issuer:    "https://identity-service.argoproj.github.io",
					Subject:   "test-user@argoproj.github.io",
					Expiry:    &testExpiry,
					NotBefore: nil,
					IssuedAt:  &testissuedAt,
				},
				Groups:             nil,
				ServiceAccountName: "",
			},
		},
		{
			description:    "unmarshal no data",
			data:           `{}`,
			expectedErr:    nil,
			expectedClaims: &Claims{},
		},
	}
	for _, test := range tests {
		CustomGroupClaimName = test.customClaimName

		claims := &Claims{}
		err := json.Unmarshal([]byte(test.data), &claims)

		assert.Equal(t, test.expectedErr, err, test.description)
		assert.Equal(t, test.expectedClaims, claims, test.description)
	}
}

func TestMarshalJSON(t *testing.T) {
	tests := []struct {
		description          string
		claims               *Claims
		customClaimName      string
		expectedClaimsString string
		expectedErr          error
	}{
		{
			description:     "marshal valid data",
			customClaimName: "ad_groups",
			expectedErr:     nil,
			claims: &Claims{
				Claims: jwt.Claims{
					ID:       "345sd435d454356",
					Audience: jwt.Audience{"example-aud"},
					Issuer:   "https://identity-service.argoproj.github.io",
					Subject:  "test-user@argoproj.github.io",
				},
				Groups: []string{"argo_admin", "argo_readonly"},
			},
			expectedClaimsString: `{"ad_groups":["argo_admin","argo_readonly"],"aud":["example-aud"],"iss":"https://identity-service.argoproj.github.io","jti":"345sd435d454356","sub":"test-user@argoproj.github.io"}`,
		},
		{
			description: "marshal valid data, with no custom group name defined",
			expectedErr: nil,
			claims: &Claims{
				Claims: jwt.Claims{
					ID:       "345sd435d454356",
					Audience: jwt.Audience{"example-aud"},
					Issuer:   "https://identity-service.argoproj.github.io",
					Subject:  "test-user@argoproj.github.io",
				},
				Groups: []string{"argo_admin", "argo_readonly"},
			},
			expectedClaimsString: `{"aud":["example-aud"],"groups":["argo_admin","argo_readonly"],"iss":"https://identity-service.argoproj.github.io","jti":"345sd435d454356","sub":"test-user@argoproj.github.io"}`,
		},
	}

	for _, test := range tests {
		CustomGroupClaimName = test.customClaimName

		out, err := json.Marshal(test.claims)

		assert.Equal(t, test.expectedErr, err)
		assert.Equal(t, test.expectedClaimsString, string(out), test.description)
	}
}
