package main

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ohsu-comp-bio/funnel/config"
	"github.com/ohsu-comp-bio/funnel/plugins/proto"
	"github.com/ohsu-comp-bio/funnel/plugins/shared"

	"github.com/hashicorp/go-plugin"
	"github.com/ohsu-comp-bio/funnel/tes"
)

type Authorize struct{}

// The OIDC client was created in Gen3 with:
// `fence-create client-create --client CLIENT_NAME --grant-types client_credentials`
type PluginConfig struct {
	S3Url            string
	OidcTokenUrl     string
	OidcClientId     string
	OidcClientSecret string
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func (a Authorize) PluginAction(params map[string]string, headers map[string]*proto.StringList, configuration *config.Config, task *tes.Task, taskType proto.Type) (*proto.JobResponse, error) {
	pluginConfig := PluginConfig{}
	ok := true
	pluginConfig.S3Url, ok = params["s3_url"]
	if !ok || pluginConfig.S3Url == "" {
		return &proto.JobResponse{
				Code:    400,
				Message: "s3_url is required in params"},
			fmt.Errorf("s3_url is required in params")
	}
	pluginConfig.OidcTokenUrl, ok = params["oidc_token_url"]
	if !ok || pluginConfig.OidcTokenUrl == "" {
		return &proto.JobResponse{
				Code:    400,
				Message: "oidc_token_url is required in params"},
			fmt.Errorf("oidc_token_url is required in params")
	}
	pluginConfig.OidcClientId, ok = params["oidc_client_id"]
	if !ok || pluginConfig.OidcClientId == "" {
		return &proto.JobResponse{
				Code:    400,
				Message: "oidc_client_id is required in params"},
			fmt.Errorf("oidc_client_id is required in params")
	}
	pluginConfig.OidcClientSecret, ok = params["oidc_client_secret"]
	if !ok || pluginConfig.OidcClientSecret == "" {
		return &proto.JobResponse{
				Code:    400,
				Message: "oidc_client_secret is required in params"},
			fmt.Errorf("oidc_client_secret is required in params")
	}
	shared.Logger.Info("Configuration", "S3Url", pluginConfig.S3Url)
	shared.Logger.Info("Configuration", "OidcTokenUrl", pluginConfig.OidcTokenUrl)
	shared.Logger.Info("Configuration", "OidcClientId", pluginConfig.OidcClientId)

	authHeader, ok := headers["authorization"]
	if !ok || authHeader == nil || len(authHeader.Values) == 0 {
		return &proto.JobResponse{
				Code:    400,
				Message: "Authorization header is required"},
			fmt.Errorf("Authorization header is required")
	}
	user := authHeader.Values[0]
	if user == "" {
		return &proto.JobResponse{
				Code:    400,
				Message: "user is required in the Auth header"},
			fmt.Errorf("user is required in the Auth header")
	}
	shared.Logger.Info("Header", "user", user)

	// exchange the OIDC client ID and secret for an access token
	httpClient := &http.Client{Timeout: 10 * time.Second}
	body, _ := json.Marshal(map[string]string{
		"scope": "openid user",
	})
	auth := base64.StdEncoding.EncodeToString([]byte(pluginConfig.OidcClientId + ":" + pluginConfig.OidcClientSecret))
	req, err := http.NewRequest("POST", pluginConfig.OidcTokenUrl+"/oauth2/token?grant_type=client_credentials", bytes.NewBuffer(body))
	if err != nil {
		return &proto.JobResponse{
				Code:    500,
				Message: fmt.Sprintf("error creating HTTP request: %w", err)},
			fmt.Errorf("error creating HTTP request: %w", err)
	}
	req.Header.Add("Authorization", "Basic "+auth)
	tokenResp, err := httpClient.Do(req)
	if err != nil {
		return &proto.JobResponse{
				Code:    500,
				Message: fmt.Sprintf("error making HTTP request: %w", err)},
			fmt.Errorf("error making HTTP request: %w", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != 200 {
		return &proto.JobResponse{
				Code:    int64(tokenResp.StatusCode),
				Message: fmt.Sprintf("http error: status code %d", tokenResp.StatusCode)},
			fmt.Errorf("http error: status code %d", tokenResp.StatusCode)
	}
	accessTokenResponse := new(AccessTokenResponse)
	err = json.NewDecoder(tokenResp.Body).Decode(accessTokenResponse)
	if err != nil {
		return &proto.JobResponse{
				Code:    500,
				Message: fmt.Sprintf("could not parse response body: %w", err)},
			fmt.Errorf("could not parse response body: %w", err)
	}

	switch taskType {
	case proto.Type_CREATE:
		configuration.AmazonS3.Disabled = true
		configuration.GenericS3 = []*config.GenericS3Storage{
			{
				Endpoint: pluginConfig.S3Url,
				Key:      accessTokenResponse.AccessToken + ";userId=" + user, // TODO
				Secret:   "N/A",
				Bucket:   "gen3wf-pauline-planx-pla-net-16", // TODO
				Region:   "us-east-1",                       // TODO
			},
		}
		return &proto.JobResponse{Code: http.StatusOK, Config: configuration, Task: task}, nil
	case proto.Type_GET, proto.Type_CANCEL:
		return &proto.JobResponse{Code: http.StatusOK, Config: configuration, Task: task}, nil
	default:
		return &proto.JobResponse{
				Code:    400,
				Message: fmt.Sprintf("unsupported task type: %v", taskType)},
			fmt.Errorf("unsupported task type: %v", taskType)
	}
}

func main() {
	log.Println("Server: registering gob types")
	gob.Register(&config.TimeoutConfig_Duration{})
	gob.Register(&config.TimeoutConfig_Disabled{})

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: shared.Handshake,
		Plugins: map[string]plugin.Plugin{
			"authorize": &shared.AuthorizePlugin{Impl: &Authorize{}},
		},

		// A non-nil value here enables gRPC serving for this plugin...
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
