package main

import (
	"os"

	"github.com/xdx888999/AScan/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
