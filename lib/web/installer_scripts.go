package web

import (
	_ "embed"
	"text/template"
)

//go:embed scripts/install-deb.sh.tmpl
var debInstaller string

// DebInstallerTemplate is a templated ubuntu/debian installer script
var DebInstallerTemplate = template.Must(template.New("deb-installer").Parse(debInstaller))
