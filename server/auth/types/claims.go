package types

import (
	"encoding/json"

	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	CustomGroupClaimName = ""
)

type Claims struct {
	jwt.Claims
	Groups             []string `json:"groups,omitempty"`
	Email              string   `json:"email,omitempty"`
	EmailVerified      bool     `json:"email_verified,omitempty"`
	ServiceAccountName string   `json:"service_account_name,omitempty"`
}

func (c *Claims) UnmarshalJSON(data []byte) error {
	claimData := make(map[string]interface{})

	err := json.Unmarshal(data, &claimData)
	if err != nil {
		return err
	}

	newClaims, err := mapToStruct(claimData)
	if err != nil {
		return err
	}

	*c = newClaims

	return nil
}

func (c *Claims) MarshalJSON() ([]byte, error) {
	// load the claim struct into a map
	claimData, err := structToMap(*c)
	if err != nil {
		return nil, err
	}

	return json.Marshal(claimData)
}

func mapToStruct(inputClaimData map[string]interface{}) (Claims, error) {
	if CustomGroupClaimName != "" {
		inputClaimData["groups"] = inputClaimData[CustomGroupClaimName]
		delete(inputClaimData, CustomGroupClaimName)
	}

	data, err := json.Marshal(inputClaimData)
	if err != nil {
		return Claims{}, err
	}

	type claimAlias Claims
	var localClaim claimAlias = claimAlias{}

	err = json.Unmarshal(data, &localClaim)
	if err != nil {
		return Claims{}, err
	}

	return Claims(localClaim), nil
}

func structToMap(inputClaim Claims) (map[string]interface{}, error) {
	type claimAlias Claims
	var localClaim claimAlias = claimAlias(inputClaim)

	data, err := json.Marshal(localClaim)
	if err != nil {
		return nil, err
	}
	returnClaims := make(map[string]interface{})
	err = json.Unmarshal(data, &returnClaims)
	if err != nil {
		return nil, err
	}

	if CustomGroupClaimName != "" {
		returnClaims[CustomGroupClaimName] = returnClaims["groups"]
		delete(returnClaims, "groups")
	}

	return returnClaims, nil
}
