package config

import (
	"bytes"
	"text/template"

	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
)

type SSHServiceFlags struct {
	AuthServersAddr []string
	AuthToken       string
	JoinMethod      string
	SSHStaticLabels map[string]string
	SSHDynamcLabels services.CommandLabels

	RawLabels string
}

// MakeDatabaseAgentConfigString generates a simple database agent
// configuration based on the flags provided. Returns the configuration as a
// string.
func MakeSSHServiceConfigString(flags SSHServiceFlags) (string, error) {
	err := flags.CheckAndSetDefaults()
	if err != nil {
		return "", trace.Wrap(err)
	}

	buf := new(bytes.Buffer)
	err = sshAgentConfigurationTemplate.Execute(buf, flags)
	if err != nil {
		return "", trace.Wrap(err)
	}

	return buf.String(), nil
}

// CheckAndSetDefaults checks and sets default values for the flags.
func (f *SSHServiceFlags) CheckAndSetDefaults() error {
	if f.RawLabels != "" {
		var err error
		f.SSHStaticLabels, f.SSHDynamcLabels, err = parseLabels(f.RawLabels)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

var sshAgentConfigurationTemplate = template.Must(
	template.New("").Funcs(databaseConfigTemplateFuncs).Parse(`
teleport:
  auth_servers:
  {{- range .AuthServersAddr }}
  - {{ . }}
  {{- end}}
  join_params:
    token_name: {{ .AuthToken }}
    method: {{ .JoinMethod }}
ssh_service:
  enabled: yes
  {{- if .SSHStaticLabels }}
  static_labels:
  {{- range $name, $value := .SSHStaticLabels }}
    "{{ $name }}": "{{ $value }}"
  {{- end }}
  {{- end }}
`))
