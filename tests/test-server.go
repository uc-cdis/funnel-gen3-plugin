package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/ohsu-comp-bio/funnel/config"
	"github.com/ohsu-comp-bio/funnel/plugins/proto"
	"github.com/ohsu-comp-bio/funnel/plugins/shared"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	csvFile = flag.String("users-csv", "example-users.csv", "Path to the CSV file containing user tokens")
)

func main() {
	flag.Parse() // Parse the command-line flags

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/token", tokenHandler)

	fmt.Printf("Server is running on http://0.0.0.0:8080 using users from: %s\n", *csvFile)
	err := http.ListenAndServe("0.0.0.0:8080", nil)
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}

// Handler for root endpoint
func indexHandler(w http.ResponseWriter, r *http.Request) {
	resp := &proto.JobResponse{ // Note the pointer here
		Code:    http.StatusOK,
		Message: "Hello, world! To get a token, send a GET request to /token?user=[USER]",
	}
	encodeResponse(w, resp)
}

func handleRequest(w http.ResponseWriter, r *http.Request, httpMethod string, user string) (*config.Config, int, *proto.Job) {
	fmt.Println("Received token request:", r)

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
		return nil, 0, nil
	}
	defer r.Body.Close()

	receivedData := &proto.Job{}
	unmarshalOptions := protojson.UnmarshalOptions{
		DiscardUnknown: true, // Or false, depending on your needs
	}

	err = unmarshalOptions.Unmarshal(bodyBytes, receivedData)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to unmarshal GetRequest from JSON using protojson: %v", err), http.StatusBadRequest)
		return nil, 0, nil
	}

	// Now you can access the parsed config and task objects
	fmt.Printf("Received Config: %#v\n", receivedData.Config)
	fmt.Printf("Received Task: %#v\n", receivedData.Task)
	fmt.Printf("Received Headers: %#v\n", receivedData.Headers)

	// Load users from the CSV file specified by the flag
	userConfig, permPass, err := loadUser(*csvFile, httpMethod, user)
	if err != nil {
		fmt.Println("Error loading users:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil, 0, nil
	}

	return userConfig, permPass, receivedData
}

// Handler for retrieving user tokens
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	var config *config.Config
	var authPass int
	var receivedData *proto.Job
	user := r.URL.Query().Get("user")
	switch r.Method {
	case http.MethodGet:
		config, authPass, receivedData = handleRequest(w, r, http.MethodGet, user)
	case http.MethodDelete:
		config, authPass, receivedData = handleRequest(w, r, http.MethodDelete, user)
	case http.MethodPut:
		config, authPass, receivedData = handleRequest(w, r, http.MethodPut, user)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}

	if config == nil {
		resp := proto.JobResponse{
			Code:    http.StatusBadRequest,
			Message: "User is required",
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	if config != nil && authPass == 1 {
		shared.Logger.Debug("Found token for user:", user, "config Key:", config.AmazonS3.AWSConfig.Key)
		receivedData.Config.AmazonS3.AWSConfig.Key = config.AmazonS3.AWSConfig.Key
		receivedData.Config.AmazonS3.AWSConfig.Secret = config.AmazonS3.AWSConfig.Secret
		encodeResponse(w, &proto.JobResponse{Code: http.StatusOK, Config: receivedData.Config, Task: receivedData.Task})
	} else {
		shared.Logger.Warn("User not authorized:", user)
		encodeResponse(w, &proto.JobResponse{Code: http.StatusUnauthorized, Message: "User not authorized", Config: receivedData.Config, Task: receivedData.Task})
	}
}

func encodeResponse(w http.ResponseWriter, resp *proto.JobResponse) {
	w.WriteHeader(int(resp.Code))
	marshalOptions := protojson.MarshalOptions{} // You can customize options if needed
	responseBody, err := marshalOptions.Marshal(resp)
	if err != nil {
		shared.Logger.Error("Error marshaling protojson response:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json") // Important: Set the correct Content-Type
	w.Write(responseBody)
}

// Load user tokens from the CSV file
func loadUser(filename string, method string, user string) (*config.Config, int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read CSV: %w", err)
	}

	var methodPass int
	userConfig := &config.Config{
		AmazonS3: &config.AmazonS3Storage{
			AWSConfig: &config.AWSConfig{},
		},
	}
	mutex := sync.RWMutex{}
	for i, row := range records {
		if i == 0 {
			continue // Skip header
		}
		if row[0] == user {
			mutex.Lock()
			switch method {
			case http.MethodGet:
				methodPass, _ = strconv.Atoi(row[3])
			case http.MethodPut:
				methodPass, _ = strconv.Atoi(row[4])
			case http.MethodDelete:
				methodPass, _ = strconv.Atoi(row[5])
			}
			userConfig.AmazonS3.AWSConfig.Key = row[1]
			userConfig.AmazonS3.AWSConfig.Secret = row[2]
			mutex.Unlock()
			return userConfig, methodPass, nil
		}
	}
	return nil, 0, nil
}
