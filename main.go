package main

import (
	"crypto/x509"
	"fmt"
	"net/http"

	"io/ioutil"

	"encoding/base64"
	"encoding/xml"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

func main() {

	rawMetadata, err := ioutil.ReadFile("GoogleIDPMetadata-redstone.biz.xml")
	if err != nil {
		panic(err)
	}

	metadata := &types.EntityDescriptor{}
	err = xml.Unmarshal(rawMetadata, metadata)
	if err != nil {
		panic(err)
	}

	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}

	for _, kd := range metadata.IDPSSODescriptor.KeyDescriptors {
		for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if xcert.Data == "" {
				panic(fmt.Errorf("metadata certificate(%d) must not be empty", idx))
			}
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err != nil {
				panic(err)
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				panic(err)
			}

			certStore.Roots = append(certStore.Roots, idpCert)
		}
	}

	// We sign the AuthnRequest with a random key because Okta doesn't seem
	// to verify these.
	randomKeyStore := dsig.RandomKeyStoreForTest()

	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      metadata.IDPSSODescriptor.SingleSignOnServices[0].Location,
		IdentityProviderIssuer:      metadata.EntityID,
		ServiceProviderIssuer:       "saml-test",
		AssertionConsumerServiceURL: "https://localhost:8080/v1/_saml_callback",
		SignAuthnRequests:           true,
		AudienceURI:                 "saml-test",
		IDPCertificateStore:         &certStore,
		SPKeyStore:                  randomKeyStore,
		AllowMissingAttributes:      true,
	}

	http.HandleFunc("/v1/_saml_callback", func(rw http.ResponseWriter, req *http.Request) {
		fmt.Println("aaaa")
		err := req.ParseForm()
		if err != nil {
			fmt.Println("ParseForm")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		response, err := sp.ValidateEncodedResponse(req.FormValue("SAMLResponse"))
		if err != nil {
			fmt.Println("ValidateEncodedResponse")
			fmt.Println(err)
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		fmt.Println(response.Assertions)

		assertion := response.Assertions[0]

		warningInfo, err := sp.VerifyAssertionConditions(&assertion)

		if err != nil {
			fmt.Println("VerifyAssertionConditions")
			fmt.Println(err)
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		fmt.Println(warningInfo)

		attributeStatement := assertion.AttributeStatement
		if attributeStatement == nil && !sp.AllowMissingAttributes {
			fmt.Println("AllowMissingAttributes")
			fmt.Println(err)
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		assertionInfo, err := sp.RetrieveAssertionInfo(req.FormValue("SAMLResponse"))
		if err != nil {
			fmt.Println("RetrieveAssertionInfo")
			fmt.Println(err)
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		if assertionInfo.WarningInfo.InvalidTime {
			fmt.Println("InvalidTime")
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		if assertionInfo.WarningInfo.NotInAudience {
			fmt.Println("NotInAudience")
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		fmt.Fprintf(rw, "NameID: %s\n", assertionInfo.NameID)

		fmt.Fprintf(rw, "Assertions:\n")

		for key, val := range assertionInfo.Values {
			fmt.Fprintf(rw, "  %s: %+v\n", key, val)
		}

		fmt.Fprintf(rw, "\n")

		fmt.Fprintf(rw, "Warnings:\n")
		fmt.Fprintf(rw, "%+v\n", assertionInfo.WarningInfo)
	})

	println("Visit this URL To Authenticate:")
	authURL, err := sp.BuildAuthURL("")
	if err != nil {
		panic(err)
	}

	println(authURL)

	println("Supply:")
	fmt.Printf("  SP ACS URL      : %s\n", sp.AssertionConsumerServiceURL)

	err = http.ListenAndServeTLS(":8080", "debug.crt", "debug.key", nil)
	if err != nil {
		panic(err)
	}
}
