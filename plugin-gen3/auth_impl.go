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

type StorageInfoResponse struct {
	Bucket string `json:"bucket"`
	Region string `json:"region"`
}

func validateTokenAndExtractUserId(token string) (string, error) {
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
				Code:    http.StatusBadRequest,
				Message: fmt.Sprintf("unsupported task type: %v", taskType),
			},
			fmt.Errorf("unsupported task type: %v", taskType)
	}

	// get the plugin configuration
	// The OIDC client should be created in Gen3 with:
	// `fence-create client-create --client CLIENT_NAME --grant-types client_credentials`
	S3Url, ok := params["S3Url"]
	if !ok || S3Url == "" {
		return &proto.JobResponse{
				Code:    http.StatusBadRequest,
				Message: "S3Url is required in params",
			},
			fmt.Errorf("S3Url is required in params")
	}
	OidcClientId, ok := params["OidcClientId"]
	if !ok || OidcClientId == "" {
		return &proto.JobResponse{
				Code:    http.StatusBadRequest,
				Message: "OidcClientId is required in params",
			},
			fmt.Errorf("OidcClientId is required in params")
	}
	OidcClientSecret, ok := params["OidcClientSecret"]
	if !ok || OidcClientSecret == "" {
		return &proto.JobResponse{
				Code:    http.StatusBadRequest,
				Message: "OidcClientSecret is required in params",
			},
			fmt.Errorf("OidcClientSecret is required in params")
	}
	shared.Logger.Info("Configuration", "S3Url", S3Url, "OidcClientId", OidcClientId)

	// get the user's access token from the headers
	authHeaders, ok := headers["authorization"]
	if !ok || authHeaders == nil || len(authHeaders.Values) == 0 {
		return &proto.JobResponse{
				Code:    http.StatusBadRequest,
				Message: "Authorization header is required",
			},
			fmt.Errorf("Authorization header is required")
	}
	authHeader := authHeaders.Values[0]
	if authHeader == "" {
		return &proto.JobResponse{
				Code:    http.StatusBadRequest,
				Message: "Authorization header is required",
			},
			fmt.Errorf("Authorization header is required")
	}

	// validate the user's token and extract the user ID
	userJWT := strings.TrimPrefix(authHeader, "Bearer ")
	userJWT = strings.TrimPrefix(userJWT, "bearer ")
	userId, err := validateTokenAndExtractUserId(userJWT)
	if err != nil {
		return &proto.JobResponse{
				Code:    http.StatusUnauthorized,
				Message: fmt.Sprintf("unable to parse token: %w", err),
			},
			fmt.Errorf("unable to parse token: %w", err)
	}

	// get the S3 bucket and region for this user
	httpClient := &http.Client{Timeout: 10 * time.Second}
	url := "http://gen3-workflow-service/storage/info"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return &proto.JobResponse{
				Code:    http.StatusInternalServerError,
				Message: fmt.Sprintf("error creating HTTP request to '%s': %w", url, err),
			},
			fmt.Errorf("error creating HTTP request to '%s': %w", url, err)
	}
	req.Header.Add("Authorization", "bearer "+userJWT)
	resp, err := httpClient.Do(req)
	if err != nil {
		return &proto.JobResponse{
				Code:    http.StatusInternalServerError,
				Message: fmt.Sprintf("error making HTTP request to '%s': %w", url, err),
			},
			fmt.Errorf("error making HTTP request to '%s': %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &proto.JobResponse{
				Code:    int64(resp.StatusCode),
				Message: fmt.Sprintf("http error from '%s': status code %d", url, resp.StatusCode),
			},
			fmt.Errorf("http error from '%s': status code %d", url, resp.StatusCode)
	}
	storageInfoResponse := new(StorageInfoResponse)
	err = json.NewDecoder(resp.Body).Decode(storageInfoResponse)
	if err != nil {
		return &proto.JobResponse{
				Code:    http.StatusInternalServerError,
				Message: fmt.Sprintf("could not parse '%s' response body: %w", url, err),
			},
			fmt.Errorf("could not parse '%s' response body: %w", url, err)
	}
	shared.Logger.Info("User's storage", "Bucket", storageInfoResponse.Bucket, "Region", storageInfoResponse.Region)

	// exchange the OIDC client ID and secret for an access token
	body, _ := json.Marshal(map[string]string{
		"scope": "openid user",
	})
	url = "http://fence-service/oauth2/token?grant_type=client_credentials"
	req, err = http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return &proto.JobResponse{
				Code:    http.StatusInternalServerError,
				Message: fmt.Sprintf("error creating HTTP request to '%s': %w", url, err),
			},
			fmt.Errorf("error creating HTTP request to '%s': %w", url, err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte(OidcClientId + ":" + OidcClientSecret))
	req.Header.Add("Authorization", "Basic "+auth)
	resp, err = httpClient.Do(req)
	if err != nil {
		return &proto.JobResponse{
				Code:    http.StatusInternalServerError,
				Message: fmt.Sprintf("error making HTTP request to '%s': %w", url, err),
			},
			fmt.Errorf("error making HTTP request to '%s': %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &proto.JobResponse{
				Code:    int64(resp.StatusCode),
				Message: fmt.Sprintf("http error from '%s': status code %d", url, resp.StatusCode),
			},
			fmt.Errorf("http error from '%s': status code %d", url, resp.StatusCode)
	}
	accessTokenResponse := new(AccessTokenResponse)
	err = json.NewDecoder(resp.Body).Decode(accessTokenResponse)
	if err != nil {
		return &proto.JobResponse{
				Code:    http.StatusInternalServerError,
				Message: fmt.Sprintf("could not parse '%s' response body: %w", url, err),
			},
			fmt.Errorf("could not parse '%s' response body: %w", url, err)
	}

	// generate and return the worker configuration
	configuration.AmazonS3.Disabled = true
	configuration.GenericS3 = []*config.GenericS3Storage{
		{
			Disabled: false,
			Endpoint: S3Url,
			Key:      accessTokenResponse.AccessToken + ";userId=" + userId,
			Secret:   "N/A",
			Bucket:   storageInfoResponse.Bucket,
			Region:   storageInfoResponse.Region,
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
