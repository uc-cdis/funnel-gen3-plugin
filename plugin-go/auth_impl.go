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

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func (Authorize) Get(userId string, host string, jsonConfig string) ([]byte, error) {
	// Funnel gets `user` from the TES task "User" tag
	if userId == "" {
		return nil, fmt.Errorf("userId is required (e.g. ./authorize <USER>)")
	}

	shared.Logger.Info("Response", "jsonConfig=", jsonConfig)
	// The OIDC client was created in Gen3 with:
	// `fence-create client-create --client CLIENT_NAME --grant-types client_credentials`
	conf := config.Config{}
	// TODO get client creds and fence url from plugin config (likely can't use revproxy since fence
	// runs in a different namespace)
	shared.Logger.Info("Response", "config=", conf)
	shared.Logger.Info("Response", "GenericS3=", conf.GenericS3)
	clientId := conf.GenericS3[0].Key
	shared.Logger.Info("Response", "clientId=", clientId)
	clientSecret := conf.GenericS3[0].Secret
	gen3FenceUrl := "https://pauline.planx-pla.net/user"

	httpClient := &http.Client{Timeout: 10 * time.Second}
	body, _ := json.Marshal(map[string]string{
		"scope": "openid user",
	})
	auth := base64.StdEncoding.EncodeToString([]byte(clientId + ":" + clientSecret))
	req, err := http.NewRequest("POST", gen3FenceUrl+"/oauth2/token?grant_type=client_credentials", bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Add("Authorization", "Basic "+auth)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	shared.Logger.Info("Response", "status", resp.Status)
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
	shared.Logger.Info("Response", "body", accessTokenResponse)
	shared.Logger.Info("Response", "userId", userId)
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
