package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"example.com/shared"
	"github.com/hashicorp/go-plugin"
)

// Here is a real implementation of Authorize that retrieves a "Secret" value for a user
type Authorize struct{}

// The OIDC client was created in Gen3 with:
// `fence-create client-create --client CLIENT_NAME --grant-types client_credentials`
type PluginConfig struct {
	OidcTokenUrl     string `json:"oidc_token_url"`
	OidcClientId     string `json:"oidc_client_id"`
	OidcClientSecret string `json:"oidc_client_secret"`
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func (Authorize) Get(userId string, host string, jsonConfig string) ([]byte, error) {
	// Funnel gets `user` from the TES task "User" tag
	if userId == "" {
		return nil, fmt.Errorf("userId is required (e.g. ./authorize <USER>)")
	}

	pluginConfig := PluginConfig{}
	err := json.Unmarshal([]byte(jsonConfig), &pluginConfig)
	if nil != err {
		return nil, fmt.Errorf("unable to parse JSON configuration: %w", err)
	}
	shared.Logger.Info("Configuration", "OidcTokenUrl", pluginConfig.OidcTokenUrl)
	shared.Logger.Info("Configuration", "OidcClientId", pluginConfig.OidcClientId)

	httpClient := &http.Client{Timeout: 10 * time.Second}
	body, _ := json.Marshal(map[string]string{
		"scope": "openid user",
	})
	auth := base64.StdEncoding.EncodeToString([]byte(pluginConfig.OidcClientId + ":" + pluginConfig.OidcClientSecret))
	req, err := http.NewRequest("POST", pluginConfig.OidcTokenUrl+"/oauth2/token?grant_type=client_credentials", bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Add("Authorization", "Basic "+auth)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	shared.Logger.Info("Token request", "status", resp.Status)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http error: status code %d", resp.StatusCode)
	}
	// respBody, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	return nil, fmt.Errorf("error reading response body: %w", err)
	// }

	accessTokenResponse := new(AccessTokenResponse)
	err = json.NewDecoder(resp.Body).Decode(accessTokenResponse)
	if err != nil {
		return nil, fmt.Errorf("could not parse response body: %v", err)
	}
	shared.Logger.Info("Response", "cred", accessTokenResponse.AccessToken+";userId="+userId)
	shared.Logger.Info("Response", "cred bytes", []byte(accessTokenResponse.AccessToken+";userId="+userId))

	var resp shared.Response
	err = json.Unmarshal([]byte(rawResp), &resp)
	if err != nil {
		return nil, fmt.Errorf("within plugin code, failed to parse plugin response: %w", err)
	}
	shared.Logger.Info("Response", "parsed resp Message", resp.Message)
	shared.Logger.Info("Response", "parsed resp Config", resp.Config)

	return []byte(accessTokenResponse.AccessToken + ";userId=" + userId), nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: shared.Handshake,
		Plugins: map[string]plugin.Plugin{
			"authorize": &shared.AuthorizePlugin{Impl: &Authorize{}},
		},

		// A non-nil value here enables gRPC serving for this plugin...
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
