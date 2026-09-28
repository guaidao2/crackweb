// crackweb —— traffic-driven web DAST scanner
//
// Maintained by guaidao2 & coolmoon
package main

import (
	"os"

	"github.com/guaidao2/crackweb/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
