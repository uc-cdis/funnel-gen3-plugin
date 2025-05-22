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
	"github.com/ohsu-comp-bio/funnel/config"
)

// Here is a real implementation of Authorize that retrieves a "Secret" value for a user
type Authorize struct{}

// The OIDC client was created in Gen3 with:
// `fence-create client-create --client CLIENT_NAME --grant-types client_credentials`
type PluginConfig struct {
	S3Url            string `json:"s3_url"`
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
	shared.Logger.Info("Configuration", "S3Url", pluginConfig.S3Url)
	shared.Logger.Info("Configuration", "OidcTokenUrl", pluginConfig.OidcTokenUrl)
	shared.Logger.Info("Configuration", "OidcClientId", pluginConfig.OidcClientId)

	// exchange the OIDC client ID and secret for an access token
	httpClient := &http.Client{Timeout: 10 * time.Second}
	body, _ := json.Marshal(map[string]string{
		"scope": "openid user",
	})
	auth := base64.StdEncoding.EncodeToString([]byte(pluginConfig.OidcClientId + ":" + pluginConfig.OidcClientSecret))
	req, err := http.NewRequest("POST", pluginConfig.OidcTokenUrl+"/oauth2/token?grant_type=client_credentials", bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP request: %w", err)
	}
	req.Header.Add("Authorization", "Basic "+auth)
	tokenResp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making HTTP request: %w", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != 200 {
		return nil, fmt.Errorf("http error: status code %d", tokenResp.StatusCode)
	}
	accessTokenResponse := new(AccessTokenResponse)
	err = json.NewDecoder(tokenResp.Body).Decode(accessTokenResponse)
	if err != nil {
		return nil, fmt.Errorf("could not parse response body: %w", err)
	}

	// generate the plugin response
	returnedConfig := config.Config{}
	returnedConfig.AmazonS3.Disabled = true
	returnedConfig.GenericS3 = []config.GenericS3Storage{
		{
			Disabled: false,
			Endpoint: pluginConfig.S3Url,
			Key:      accessTokenResponse.AccessToken + ";userId=" + userId,
			Secret:   "N/A",
		},
	}
	pluginResp := &shared.Response{
		Code: http.StatusOK,
		// Message: "",
		Config: &returnedConfig,
	}
	pluginRespStr, err := json.Marshal(pluginResp)
	if err != nil {
		return nil, fmt.Errorf("unable to stringify response: %w", err)
	}

	return []byte(pluginRespStr), nil
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
