module github.com/guaidao2/crackweb

go 1.26.0

// The toolchain the published binaries are built with. This line is a floor —
// Go upgrades an older toolchain to it but keeps a newer local one — so the
// exact pin for a release build is GOTOOLCHAIN, set by the release workflow and
// by the Makefile's release target. A different patch release builds a
// different binary from the same source, and the workflow checks the artifact
// against this line rather than trusting the runner's default Go.
toolchain go1.26.4

require (
	github.com/chromedp/cdproto v0.0.0-20260714215040-dc233986426f // indirect
	github.com/chromedp/chromedp v0.16.0 // indirect
	github.com/chromedp/sysutil v1.1.0 // indirect
	github.com/go-json-experiment/json v0.0.0-20260623181947-01eb4420fa68 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
