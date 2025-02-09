package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

func main() {
	fmt.Println("app started")

	clientID := os.Getenv("REPORT_APP_KEYCLOAK_CLIENT_ID")
	clientSecret := os.Getenv("REPORT_APP_KEYCLOAK_CLIENT_SECRET")
	keycloakAddr := os.Getenv("REPORT_APP_KEYCLOAK_ADDR")

	if clientID == "" || clientSecret == "" || keycloakAddr == "" {
		panic("client auth params are empty")
	}

	fmt.Println("client id: ", clientID)
	fmt.Println("client secret: ", clientSecret)

	h := newHandler(clientID, clientSecret, keycloakAddr)

	m := http.NewServeMux()
	m.HandleFunc("OPTIONS /reports", h.handleReportsOptions)
	m.HandleFunc("GET /reports", h.handleReports)

	err := http.ListenAndServe(":8000", m)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func newHandler(id, secret, keycloak string) *basicHandler {
	return &basicHandler{
		client: &http.Client{
			Timeout: time.Second * 10,
		},
		clientID:     id,
		clientSecret: secret,
		keycloakAddr: keycloak,
	}
}

type basicHandler struct {
	client       *http.Client
	clientID     string
	clientSecret string
	keycloakAddr string
}

func (bh *basicHandler) handleReportsOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization")
	w.WriteHeader(http.StatusOK)
}

func (bh *basicHandler) handleReports(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Println("token not set: ")
		return
	}

	tc, err := bh.introspectToken(token)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Println("introspect error: ", err.Error())
		return
	}

	if !tc.Active {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Println("not active token")
		return
	}

	if !slices.Contains(tc.RealmAccess.Roles, "prothetic_user") {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Println("not role")
		return
	}

	fmt.Println("handle reports for: ", tc.Username)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(resp))
}

func (bh *basicHandler) introspectToken(token string) (*TokenClaims, error) {
	req, err := bh.makeIntrospectRequest(token)
	if err != nil {
		return nil, err
	}
	resp, err := bh.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	t, err := decodeToken(data)
	if err != nil {
		return nil, err
	}

	return t, nil
}

func (bh *basicHandler) makeIntrospectRequest(token string) (*http.Request, error) {
	u := fmt.Sprintf("%s/realms/reports-realm/protocol/openid-connect/token/introspect", bh.keycloakAddr)
	data := url.Values{}
	data.Set("token", token)
	data.Set("token_type_hint", "access_token")

	encodedData := data.Encode()

	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(encodedData))
	if err != nil {
		return nil, err
	}

	req.Host = "localhost:8080"

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	req.SetBasicAuth(bh.clientID, bh.clientSecret)

	fmt.Println(token)

	return req, nil
}

func decodeToken(token []byte) (*TokenClaims, error) {
	dec := new(TokenClaims)

	err := json.Unmarshal(token, dec)
	if err != nil {
		return nil, err
	}

	fmt.Println(string(token))

	return dec, nil
}

type TokenClaims struct {
	Active      bool   `json:"active"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

var resp = `
["value1", "value2", "value3", "value4", "value5", "value6", "value7", "value8", "value9"]
`
