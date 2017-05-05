package config

import (
	"regexp"
)

type (
	// EndpointConf is on endpoint configuration
	EndpointConf struct {
		Name         string
		Description  string
		HTTPAddress  string
		HTTPSAddress string
		SslCert      string
		SslKey       string
		Destination  string
		Autostart    bool

		Users              []string
		ClientCertificates []string

		// AcceptAddr containst list of ip/networks separated by new line
		AcceptAddr string
	}
)


// AcceptUser check is login on list users accepted to use this endpoint
func (e *EndpointConf) AcceptUser(login string) bool {
	for _, user := range e.Users {
		if user == login {
			return true
		}
	}
	return false
}

var nameValidator = regexp.MustCompile("^\\w+$")

// Validate configuration
func (e *EndpointConf) Validate() (errors map[string]string) {
	errors = make(map[string]string)
	if !nameValidator.MatchString(e.Name) {
		errors["Name"] = "Letters, numbers, and underscores only please"
	}
	if e.HTTPAddress == "" && e.HTTPSAddress == "" {
		errors["HTTPSAddress"] = "Missing local address"
	}
	if e.HTTPSAddress != "" {
		if e.SslCert == "" {
			errors["SslCert"] = "SSL Cert missing"
		}
		if e.SslKey == "" {
			errors["SslKey"] = "SSL Key missing"
		}
	}
	if e.Destination == "" {
		errors["Destination"] = "Missing Destination"
	}
	return
}

// Clone endpoint configuration structure
func (e *EndpointConf) Clone() *EndpointConf {
	ne := &EndpointConf{
		Name:         e.Name,
		Description:  e.Description,
		HTTPAddress:  e.HTTPAddress,
		HTTPSAddress: e.HTTPSAddress,
		SslCert:      e.SslCert,
		SslKey:       e.SslKey,
		Destination:  e.Destination,
		Autostart:    e.Autostart,

		Users:              make([]string, len(e.Users)),
		ClientCertificates: make([]string, len(e.ClientCertificates)),

		AcceptAddr: e.AcceptAddr,
	}

	for i, u := range e.Users {
		ne.Users[i] = u
	}

	for i, c := range e.ClientCertificates {
		ne.ClientCertificates[i] = c
	}

	return ne
}
