package main

import (
	"os"

	"github.com/njhoffman/audit/cmd/audit/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
