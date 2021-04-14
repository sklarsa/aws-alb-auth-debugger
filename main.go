package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

const (
	ACCESS_TOKEN_HEADER   = "x-amzn-oidc-accesstoken"
	IDENTITY_TOKEN_HEADER = "x-amzn-oidc-identity"
	USER_CLAIMS_HEADER    = "x-amzn-oidc-data"
)

var (
	AWS_REGION string
	//go:embed jwtinfo.html
	jwtinfoFmtStr   string
	jwtinfoTemplate *template.Template
)

func getJwtPubKey(encodedJwt string) (*ecdsa.PublicKey, error) {
	encodedHeaders := strings.Split(encodedJwt, ".")[0]
	decodedHeaders, err := jwt.DecodeSegment(encodedHeaders)
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string)
	json.Unmarshal(decodedHeaders, &headers)

	kid := headers["kid"]
	url := fmt.Sprintf("https://public-keys.auth.elb.%s.amazonaws.com/%s", AWS_REGION, kid)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GET: %s -- %s", url, resp.Status)
	}

	content, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(content)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	return pub.(*ecdsa.PublicKey), nil
}

func decodeJwt(encodedJwt string) (jwt.MapClaims, error) {
	pubKey, err := getJwtPubKey(encodedJwt)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(encodedJwt, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return pubKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}

}

func jwtInfo(w http.ResponseWriter, req *http.Request) {
	userClaimsJwt := req.Header.Get(USER_CLAIMS_HEADER)
	idToken := req.Header.Get(IDENTITY_TOKEN_HEADER)
	accessTokenJwt := req.Header.Get(ACCESS_TOKEN_HEADER)

	if userClaimsJwt == "" || idToken == "" || accessTokenJwt == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Required headers not found.  Are you running behind a load balancer?"))
		return
	}

	claims, err := decodeJwt(userClaimsJwt)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprint(err)))
		return
	}

	err = jwtinfoTemplate.Execute(w, map[string]interface{}{
		"claimsValue":       claims,
		"claimsHeader":      USER_CLAIMS_HEADER,
		"idTokenValue":      idToken,
		"idTokenHeader":     IDENTITY_TOKEN_HEADER,
		"accessTokenValue":  accessTokenJwt,
		"accessTokenHeader": ACCESS_TOKEN_HEADER,
	})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprint(err)))
	}

}

func healthcheck(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("Healthy!"))
}

func main() {
	port := flag.Int("p", 8080, "TCP port to run the server on")
	flag.StringVar(&AWS_REGION, "r", "us-east-1", "AWS Region your load balancer is running in")

	flag.Parse()

	http.HandleFunc("/", jwtInfo)
	http.HandleFunc("/health", healthcheck)

	var err error
	jwtinfoTemplate, err = template.New("jwtinfo").Parse(jwtinfoFmtStr)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("Starting server...")
	err = http.ListenAndServe(fmt.Sprintf(":%d", *port), nil)
	if err != nil {
		log.Fatal(err)
	}

}
