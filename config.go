package main

import "github.com/stvp/go-toml-config"

var (
	outDir      = config.String("outDir", "pems")
	searchTerm  = config.String("searchTerm", ".com")
	pilotKeyPEM = config.String("pilotKeyPem", "")
)
