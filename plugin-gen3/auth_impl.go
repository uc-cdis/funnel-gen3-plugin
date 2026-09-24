package main

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ohsu-comp-bio/funnel/config"
	"github.com/ohsu-comp-bio/funnel/plugins/proto"
	"github.com/ohsu-comp-bio/funnel/plugins/shared"

	"github.com/hashicorp/go-plugin"
	"github.com/ohsu-comp-bio/funnel/tes"
)

type Authorize struct{}

type StorageInfoResponse struct {
	Bucket              string `json:"bucket"`
	Region              string `json:"region"`
	S3FilesFilesystemId string `json:"s3files_filesystem_id"`
}

func errorResponse(code int64, msg string) (*proto.JobResponse, error) {
	// returning `nil` instead of the actual error here, because this response is parsed upstream
	// and a 500 is returned if the error is anything else than `nil`. The actual error code is
	// parsed from `JobResponse.code` instead.
	return &proto.JobResponse{
			Code:    code,
			Message: msg,
		},
		nil
}

func (a Authorize) PluginAction(params map[string]string, headers map[string]*proto.StringList, configuration *config.Config, task *tes.Task, taskType proto.Type) (*proto.JobResponse, error) {
	// only proceed for task creation events. The worker config does not need to be updated for
	// other types of events
	if taskType == proto.Type_GET || taskType == proto.Type_CANCEL {
		return &proto.JobResponse{Code: http.StatusOK, Config: configuration, Task: task}, nil
	}
	if taskType != proto.Type_CREATE {
		return errorResponse(http.StatusBadRequest, fmt.Sprintf("unsupported task type: %v", taskType))
	}

	// get the plugin configuration
	// The OIDC client should be created in Gen3 with:
	// `fence-create client-create --client CLIENT_NAME --grant-types client_credentials`
	S3Url, ok := params["S3Url"]
	if !ok || S3Url == "" {
		return errorResponse(http.StatusBadRequest, "S3Url is required in params")
	}

	// get the user's access token from the headers
	authHeaders, ok := headers["authorization"]
	if !ok || authHeaders == nil || len(authHeaders.Values) == 0 {
		return errorResponse(http.StatusBadRequest, "Authorization header is required")
	}
	authHeader := authHeaders.Values[0]
	if authHeader == "" {
		return errorResponse(http.StatusBadRequest, "Authorization header is required")
	}

	// validate the user's token and extract the user ID
	userJWT := strings.TrimPrefix(authHeader, "Bearer ")
	userJWT = strings.TrimPrefix(userJWT, "bearer ")

	// get the S3 bucket and region for this user
	httpClient := &http.Client{Timeout: 10 * time.Second}
	url := "http://gen3-workflow-service/storage/setup"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Errorf("error creating HTTP request to '%s': %w", url, err).Error())
	}
	req.Header.Add("Authorization", "bearer "+userJWT)
	resp, err := httpClient.Do(req)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Errorf("error making HTTP request to '%s': %w", url, err).Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return errorResponse(int64(resp.StatusCode), fmt.Errorf("http error from '%s': status code %d, body: %s", url, resp.StatusCode, string(body)).Error())
	}
	storageInfoResponse := new(StorageInfoResponse)
	err = json.NewDecoder(resp.Body).Decode(storageInfoResponse)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, fmt.Errorf("could not parse '%s' response body: %w", url, err).Error())
	}
	shared.Logger.Info("User's storage", "Bucket", storageInfoResponse.Bucket, "Region", storageInfoResponse.Region, "S3FilesFilesystemId", storageInfoResponse.S3FilesFilesystemId)

	// generate and return the worker configuration
	configuration.AmazonS3.Disabled = true
	configuration.GenericS3 = []*config.GenericS3Storage{
		{
			Disabled: false,
			Endpoint: S3Url,
			Key:      "N/A",
			Secret:   "N/A",
			Bucket:   storageInfoResponse.Bucket,
			Region:   storageInfoResponse.Region,
		},
	}
	if storageInfoResponse != nil && storageInfoResponse.S3FilesFilesystemId != "" {
		configuration.Kubernetes.S3FilesFilesystemId = storageInfoResponse.S3FilesFilesystemId
	} else {
		// Explicitly wipe out any residual value from previous runs
		configuration.Kubernetes.S3FilesFilesystemId = ""
	}
	shared.Logger.Info("Configuration", "S3FilesFilesystemId", configuration.Kubernetes.S3FilesFilesystemId)

	// parse internal tags into the appropriate configuration
	nodeSelector, ok := task.Tags["_NODE_SELECTOR"]
	if ok {
		// _NODE_SELECTOR expected format: "role:workflow"
		key, value, ok := strings.Cut(nodeSelector, ":")
		if !ok {
			return errorResponse(http.StatusInternalServerError, fmt.Sprintf("invalid _NODE_SELECTOR format: '%s'", nodeSelector))
		}
		configuration.Kubernetes.NodeSelector = map[string]string{key: value}
		shared.Logger.Info("Configuration", "NodeSelector", configuration.Kubernetes.NodeSelector)
	}
	tolerations, ok := task.Tags["_TOLERATIONS"]
	if ok {
		// _TOLERATIONS expected format: "Key:role,Operator:Equal,Value:workflow,Effect:NoSchedule"
		pairs := strings.Split(tolerations, ",")
		res := make(map[string]string)
		for _, pair := range pairs {
			key, value, ok := strings.Cut(pair, ":")
			if ok {
				res[key] = value
			}
		}
		expectedKeys := []string{"Key", "Operator", "Value", "Effect"}
		for _, k := range expectedKeys {
			if _, ok := res[k]; !ok {
				return errorResponse(http.StatusInternalServerError, fmt.Sprintf("missing _TOLERATIONS key '%s': '%s'", k, tolerations))
			}
		}
		configuration.Kubernetes.Tolerations = []*config.Toleration{
			{
				Key:      res["Key"],
				Operator: res["Operator"],
				Value:    res["Value"],
				Effect:   res["Effect"],
			},
		}
		shared.Logger.Info("Configuration", "Tolerations", configuration.Kubernetes.Tolerations)
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
