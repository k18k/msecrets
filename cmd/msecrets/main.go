// Command msecrets is the msecrets CLI and terminal UI.
package main

import (
	"os"

	"github.com/k18k/msecrets/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
