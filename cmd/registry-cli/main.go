package main

import (
	"os"

	"github.com/sirosfoundation/registry-cli/cmd/registry-cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
