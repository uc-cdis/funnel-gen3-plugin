package main

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ohsu-comp-bio/funnel/config"
	"github.com/ohsu-comp-bio/funnel/plugins/proto"
	"github.com/ohsu-comp-bio/funnel/plugins/shared"
	"github.com/uc-cdis/go-authutils/authutils"

	"github.com/hashicorp/go-plugin"
	"github.com/ohsu-comp-bio/funnel/tes"
)

type Authorize struct{}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func getUserIdFromToken(token string) (string, error) {
	// This function was copied and adapted from arborist
	// https://github.com/uc-cdis/arborist/blob/2025.05/arborist/token.go#L16

	missingRequiredField := func(field string) error {
		msg := fmt.Sprintf(
			"failed to decode token: missing required field `%s`",
			field,
		)
		return errors.New(msg)
	}
	fieldTypeError := func(field string) error {
		msg := fmt.Sprintf(
			"failed to decode token: field `%s` has wrong type",
			field,
		)
		return errors.New(msg)
	}

	jwtApp := authutils.NewJWTApplication("http://fence-service/.well-known/jwks")
	claims, err := jwtApp.Decode(token)
	if err != nil {
		return "", fmt.Errorf("error decoding token: %w", err)
	}
	scopes := []string{"openid"}
	expected := &authutils.Expected{Scopes: scopes}

	// TODO comment - allow not validating expiration in Validate()
	// actually idk? if this is only called at task creation it should be valid
	// (*claims)["exp"] = time.Now().Unix() + 60

	err = expected.Validate(claims)
	if err != nil {
		return "", fmt.Errorf("error decoding token: %w", err)
	}
	userIdInterface, exists := (*claims)["sub"]
	if !exists {
		return "", missingRequiredField("sub")
	}
	userId, casted := userIdInterface.(string)
	if !casted {
		return "", fieldTypeError("sub")
	}

	return userId, nil
}

func (a Authorize) PluginAction(params map[string]string, headers map[string]*proto.StringList, configuration *config.Config, task *tes.Task, taskType proto.Type) (*proto.JobResponse, error) {
	// only proceed for task creation events. The worker config does not need to be updated for
	// other types of events
	if taskType == proto.Type_GET || taskType == proto.Type_CANCEL {
		return &proto.JobResponse{Code: http.StatusOK, Config: configuration, Task: task}, nil
	}
	if taskType != proto.Type_CREATE {
		return &proto.JobResponse{
			Code:    400,
			Message: fmt.Sprintf("unsupported task type: %v", taskType)
		},
		fmt.Errorf("unsupported task type: %v", taskType)
	}

	// get the plugin configuration
	// The OIDC client should be created in Gen3 with:
	// `fence-create client-create --client CLIENT_NAME --grant-types client_credentials`
	S3Url, ok := params["S3Url"]
	if !ok || S3Url == "" {
		return &proto.JobResponse{
			Code:    400,
			Message: "S3Url is required in params"
		},
		fmt.Errorf("S3Url is required in params")
	}
	OidcTokenUrl, ok := params["OidcTokenUrl"]
	if !ok || OidcTokenUrl == "" {
		return &proto.JobResponse{
			Code:    400,
			Message: "OidcTokenUrl is required in params"
		},
		fmt.Errorf("OidcTokenUrl is required in params")
	}
	OidcClientId, ok := params["OidcClientId"]
	if !ok || OidcClientId == "" {
		return &proto.JobResponse{
			Code:    400,
			Message: "OidcClientId is required in params"
		},
		fmt.Errorf("OidcClientId is required in params")
	}
	OidcClientSecret, ok := params["OidcClientSecret"]
	if !ok || OidcClientSecret == "" {
		return &proto.JobResponse{
			Code:    400,
			Message: "OidcClientSecret is required in params"
		},
		fmt.Errorf("OidcClientSecret is required in params")
	}
	shared.Logger.Info("Configuration", "S3Url", S3Url)
	shared.Logger.Info("Configuration", "OidcTokenUrl", OidcTokenUrl)
	shared.Logger.Info("Configuration", "OidcClientId", OidcClientId)

	// get the user's access token from the headers
	authHeaders, ok := headers["authorization"]
	if !ok || authHeaders == nil || len(authHeaders.Values) == 0 {
		return &proto.JobResponse{
			Code:    400,
			Message: "Authorization header is required"
		},
		fmt.Errorf("Authorization header is required")
	}
	authHeader := authHeaders.Values[0]
	if authHeader == "" {
		return &proto.JobResponse{
			Code:    400,
			Message: "Authorization header is required"
		},
		fmt.Errorf("Authorization header is required")
	}

	// validate the user's token and extract the user ID
	userJWT := strings.TrimPrefix(authHeader, "Bearer ")
	userJWT = strings.TrimPrefix(userJWT, "bearer ")
	userId, err := getUserIdFromToken(userJWT)
	if err != nil {
		return &proto.JobResponse{
			Code:    401,
			Message: fmt.Sprintf("unable to parse token: %w", err)
		},
		fmt.Errorf("unable to parse token: %w", err)
	}

	// exchange the OIDC client ID and secret for an access token
	httpClient := &http.Client{Timeout: 10 * time.Second}
	body, _ := json.Marshal(map[string]string{
		"scope": "openid user",
	})
	auth := base64.StdEncoding.EncodeToString([]byte(OidcClientId + ":" + OidcClientSecret))
	// TODO try again replacing external URL with fence-service
	req, err := http.NewRequest("POST", OidcTokenUrl+"/oauth2/token?grant_type=client_credentials", bytes.NewBuffer(body))
	if err != nil {
		return &proto.JobResponse{
			Code:    500,
			Message: fmt.Sprintf("error creating HTTP request: %w", err)
		},
		fmt.Errorf("error creating HTTP request: %w", err)
	}
	req.Header.Add("Authorization", "Basic "+auth)
	tokenResp, err := httpClient.Do(req)
	if err != nil {
		return &proto.JobResponse{
			Code:    500,
			Message: fmt.Sprintf("error making HTTP request: %w", err)
		},
		fmt.Errorf("error making HTTP request: %w", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != 200 {
		return &proto.JobResponse{
			Code:    int64(tokenResp.StatusCode),
			Message: fmt.Sprintf("http error: status code %d", tokenResp.StatusCode)
		},
		fmt.Errorf("http error: status code %d", tokenResp.StatusCode)
	}
	accessTokenResponse := new(AccessTokenResponse)
	err = json.NewDecoder(tokenResp.Body).Decode(accessTokenResponse)
	if err != nil {
		return &proto.JobResponse{
			Code:    500,
			Message: fmt.Sprintf("could not parse response body: %w", err)
		},
		fmt.Errorf("could not parse response body: %w", err)
	}

	// generate and return the worker configuration
	configuration.AmazonS3.Disabled = true
	configuration.GenericS3 = []*config.GenericS3Storage{
		{
			Endpoint: S3Url,
			Key:      accessTokenResponse.AccessToken + ";userId=" + userId,
			Secret:   "N/A",
			Bucket:   "gen3wf-pauline-planx-pla-net-16", // TODO
			Region:   "us-east-1",                       // TODO
		},
	}
	return &proto.JobResponse{Code: http.StatusOK, Config: configuration, Task: task}, nil
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
