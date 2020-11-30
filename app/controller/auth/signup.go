package auth

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/twinj/uuid"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"postit-authentication-server/pkg/logs"
	"postit-authentication-server/pkg/models"
	"postit-authentication-server/pkg/utils"
	"time"
)

const cost = 10

func SignUp(w http.ResponseWriter, r *http.Request) {
	transactionId := uuid.NewV4()
	logs.Log("TransactionId: ", transactionId)

	headers, err := utils.ValidateHeaders(r)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusBadRequest)
		return
	}

	//Get the relevant headers
	traceId := headers["trace-id"]

	// Logging the headers
	log.Printf("Headers => TraceId: %s", traceId)

	body, err := ioutil.ReadAll(r.Body)
	logs.Log("Request Body in bytes: ", body)
	logs.Log("Request Body as a string: ", string(body))

	var req models.SignUpRequest

	err = json.Unmarshal(body, &req)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusBadRequest)
		return
	}
	logs.Log(req)

	logs.Log("Raw Password: ", req.Password)

	// Hash the password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), cost)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusInternalServerError)
		return
	}
	logs.Log("Hashed Password: ", passwordHash)

	// Provision schema
	tenantNamespace, err := utils.ProvisionSchema(req, passwordHash)
	if err != nil {
		utils.SendErrorSchemaMessage(w, r, err, transactionId, http.StatusBadRequest)
		return
	}

	claims := jwt.StandardClaims{
		Audience:  "PostIt",
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		Id:        uuid.NewV4().String(),
		IssuedAt:  time.Now().Unix(),
		Issuer:    "PostIt Auth",
		Subject:   "User Login Authentication",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	logs.Log("Token signature: ", token.Signature)
	logs.Log(string(PrivateKey))

	tokenString, err := token.SignedString(PrivateKey)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusInternalServerError)
		return
	}

	logs.Log("Token signature: ", token.Signature)
	logs.Log(token.Valid)

	// set the cookie
	cookie := &http.Cookie{
		Name:       "token",
		Value:      tokenString,
		Domain:     "",
		Expires:    time.Now().Add(10 * time.Minute),
		MaxAge:     time.Now().Add(11 * time.Minute).Minute(),
		Secure:     true,
		HttpOnly:   true,
	}
	http.SetCookie(w, cookie)

	w.Header().Add("tenant-namespace", tenantNamespace)
	err = json.NewEncoder(w).Encode(&models.LoginTokenResponse{
		Message: "Successfully signed up",
		Meta: models.MetaData{
			TraceId:       headers["trace-id"],
			TransactionId: transactionId.String(),
			TimeStamp:     time.Now(),
			Status:        "SUCCESS",
		},
	})
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusInternalServerError)
		return
	}
}