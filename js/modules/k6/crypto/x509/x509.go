/*
 *
 * k6 - a next-generation load testing tool
 * Copyright (C) 2019 Load Impact
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package x509

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/dop251/goja"
	"go.k6.io/k6/js/common"
	"go.k6.io/k6/js/modules"
)

type (
	// RootModule is the global module instance that will create module
	// instances for each VU.
	RootModule struct{}

	// X509 represents an instance of the X509 certificate module.
	X509 struct {
		vu  modules.VU
		obj *goja.Object
	}
)

var (
	_ modules.Module   = &RootModule{}
	_ modules.Instance = &X509{}
)

// New returns a pointer to a new RootModule instance.
func New() *RootModule {
	return &RootModule{}
}

// NewModuleInstance implements the modules.Module interface to return
// a new instance for each VU.
func (*RootModule) NewModuleInstance(vu modules.VU) modules.Instance {
	rt := vu.Runtime()
	o := rt.NewObject()
	mi := &X509{vu: vu, obj: o}

	mustExport := func(name string, value interface{}) {
		if err := mi.obj.Set(name, value); err != nil {
			common.Throw(rt, err)
		}
	}

	mustExport("parse", mi.Parse)
	mustExport("getAltNames", mi.AltNames)
	mustExport("getIssuer", mi.Issuer)
	mustExport("getSubject", mi.Subject)
	return mi
}

// Exports returns the exports of the execution module.
func (mi *X509) Exports() modules.Exports {
	return modules.Exports{Default: mi.obj}
}

// Certificate is an X.509 certificate
type Certificate struct {
	Subject            Subject
	Issuer             Issuer
	NotBefore          string    `js:"notBefore"`
	NotAfter           string    `js:"notAfter"`
	AltNames           []string  `js:"altNames"`
	SignatureAlgorithm string    `js:"signatureAlgorithm"`
	FingerPrint        []byte    `js:"fingerPrint"`
	PublicKey          PublicKey `js:"publicKey"`
}

// RDN is a component of an X.509 distinguished name
type RDN struct {
	Type  string
	Value string
}

// Subject is a certificate subject
type Subject struct {
	CommonName             string `js:"commonName"`
	Country                string
	PostalCode             string   `js:"postalCode"`
	StateOrProvinceName    string   `js:"stateOrProvinceName"`
	LocalityName           string   `js:"localityName"`
	StreetAddress          string   `js:"streetAddress"`
	OrganizationName       string   `js:"organizationName"`
	OrganizationalUnitName []string `js:"organizationalUnitName"`
	Names                  []RDN
}

// Issuer is a certificate issuer
type Issuer struct {
	CommonName          string `js:"commonName"`
	Country             string
	StateOrProvinceName string `js:"stateOrProvinceName"`
	LocalityName        string `js:"localityName"`
	OrganizationName    string `js:"organizationName"`
	Names               []RDN
}

// PublicKey is used for decryption and signature verification
type PublicKey struct {
	Algorithm string
	Key       interface{}
}

// Parse produces an entire X.509 certificate
func (mi X509) Parse(encoded []byte) Certificate {
	parsed, err := parseCertificate(encoded)
	if err != nil {
		common.Throw(mi.vu.Runtime(), err)
	}
	certificate, err := makeCertificate(parsed)
	if err != nil {
		common.Throw(mi.vu.Runtime(), err)
	}
	return certificate
}

// AltNames extracts alt names
func (mi X509) AltNames(encoded []byte) []string {
	parsed, err := parseCertificate(encoded)
	if err != nil {
		common.Throw(mi.vu.Runtime(), err)
	}
	return altNames(parsed)
}

// Issuer extracts certificate issuer
func (mi X509) Issuer(encoded []byte) Issuer {
	parsed, err := parseCertificate(encoded)
	if err != nil {
		common.Throw(mi.vu.Runtime(), err)
	}
	return makeIssuer(parsed.Issuer)
}

// Subject extracts certificate subject
func (mi X509) Subject(encoded []byte) Subject {
	parsed, err := parseCertificate(encoded)
	if err != nil {
		common.Throw(mi.vu.Runtime(), err)
	}
	return makeSubject(parsed.Subject)
}

func parseCertificate(encoded []byte) (*x509.Certificate, error) {
	decoded, _ := pem.Decode(encoded)
	if decoded == nil {
		err := errors.New("failed to decode certificate PEM file")
		return nil, err
	}
	parsed, err := x509.ParseCertificate(decoded.Bytes)
	if err != nil {
		err = fmt.Errorf("failed to parse certificate: %w", err)
		return nil, err
	}
	return parsed, nil
}

func makeCertificate(parsed *x509.Certificate) (Certificate, error) {
	publicKey, err := makePublicKey(parsed.PublicKey)
	if err != nil {
		return Certificate{}, err
	}
	return Certificate{
		Subject:            makeSubject(parsed.Subject),
		Issuer:             makeIssuer(parsed.Issuer),
		NotBefore:          iso8601(parsed.NotBefore),
		NotAfter:           iso8601(parsed.NotAfter),
		AltNames:           altNames(parsed),
		SignatureAlgorithm: signatureAlgorithm(parsed.SignatureAlgorithm),
		FingerPrint:        fingerPrint(parsed),
		PublicKey:          publicKey,
	}, nil
}

func makeSubject(subject pkix.Name) Subject {
	return Subject{
		CommonName:             subject.CommonName,
		Country:                first(subject.Country),
		PostalCode:             first(subject.PostalCode),
		StateOrProvinceName:    first(subject.Province),
		LocalityName:           first(subject.Locality),
		StreetAddress:          first(subject.StreetAddress),
		OrganizationName:       first(subject.Organization),
		OrganizationalUnitName: subject.OrganizationalUnit,
		Names:                  makeRdns(subject.Names),
	}
}

func makeIssuer(issuer pkix.Name) Issuer {
	return Issuer{
		CommonName:          issuer.CommonName,
		Country:             first(issuer.Country),
		StateOrProvinceName: first(issuer.Province),
		LocalityName:        first(issuer.Locality),
		OrganizationName:    first(issuer.Organization),
		Names:               makeRdns(issuer.Names),
	}
}

func makePublicKey(parsed interface{}) (PublicKey, error) {
	var algorithm string
	switch parsed.(type) {
	case *dsa.PublicKey:
		algorithm = "DSA"
	case *ecdsa.PublicKey:
		algorithm = "ECDSA"
	case *rsa.PublicKey:
		algorithm = "RSA"
	default:
		err := errors.New("unsupported public key algorithm")
		return PublicKey{}, err
	}
	return PublicKey{
		Algorithm: algorithm,
		Key:       parsed,
	}, nil
}

func first(values []string) string {
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

func iso8601(value time.Time) string {
	return value.Format(time.RFC3339)
}

func makeRdns(names []pkix.AttributeTypeAndValue) []RDN {
	result := make([]RDN, len(names))
	for i, name := range names {
		result[i] = makeRdn(name)
	}
	return result
}

func makeRdn(name pkix.AttributeTypeAndValue) RDN {
	return RDN{
		Type:  name.Type.String(),
		Value: fmt.Sprintf("%v", name.Value),
	}
}

func altNames(parsed *x509.Certificate) []string {
	var names []string
	names = append(names, parsed.DNSNames...)
	names = append(names, parsed.EmailAddresses...)
	names = append(names, ipAddresses(parsed)...)
	names = append(names, uris(parsed)...)
	return names
}

func ipAddresses(parsed *x509.Certificate) []string {
	strings := make([]string, len(parsed.IPAddresses))
	for i, item := range parsed.IPAddresses {
		strings[i] = item.String()
	}
	return strings
}

func uris(parsed *x509.Certificate) []string {
	strings := make([]string, len(parsed.URIs))
	for i, item := range parsed.URIs {
		strings[i] = item.String()
	}
	return strings
}

func signatureAlgorithm(value x509.SignatureAlgorithm) string {
	if value == x509.UnknownSignatureAlgorithm {
		return "UnknownSignatureAlgorithm"
	}
	return value.String()
}

func fingerPrint(parsed *x509.Certificate) []byte {
	bytes := sha1.Sum(parsed.Raw) // #nosec G401
	return bytes[:]
}
