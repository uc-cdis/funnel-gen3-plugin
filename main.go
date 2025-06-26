package main

import (
	"fmt"
	"os"

	"github.com/ohsu-comp-bio/funnel/config"
	"github.com/ohsu-comp-bio/funnel/plugins/proto"
	"github.com/ohsu-comp-bio/funnel/plugins/shared"
	"github.com/ohsu-comp-bio/funnel/tes"
)

func run(params map[string]string, header map[string]*proto.StringList,
	config *config.Config, task *tes.Task,
	taskType proto.Type, dir string) (string, error) {

	m := &shared.Manager{}
	defer m.Close()
	authorize, err := m.Client(dir)
	if err != nil {
		return "", fmt.Errorf("failed to get client: %w", err)
	}

	resp, err := authorize.PluginAction(params, header, config, task, taskType)
	if err != nil {
		return "", fmt.Errorf("failed to authorize: %w", err)
	}

	return resp.String(), nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <USER> <HOST>\n", os.Args[0])
		os.Exit(1)
	}
	user := os.Args[1]
	host := os.Args[2]
	dir := "build/plugins"
	params := map[string]string{
		"user": user,
		"host": host,
	}

	headers := map[string]*proto.StringList{}
	config := config.DefaultConfig()
	var task *tes.Task
	var taskType proto.Type

	out, err := run(params, headers, config, task, taskType, dir)
	if err != nil {
		fmt.Println("Error calling plugin:", err)
		os.Exit(1)
	}

	fmt.Println("OUT: ", out)
	os.Exit(0)
}
