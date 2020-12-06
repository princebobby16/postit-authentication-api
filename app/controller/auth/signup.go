package auth

import (
	"encoding/json"
	"github.com/cristalhq/jwt"
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
		utils.SendErrorMessage(w, r, err, "Invalid Password!", transactionId, http.StatusInternalServerError)
		return
	}
	logs.Log("Hashed Password: ", passwordHash)

	// Provision schema
	tenantNamespace, err := utils.ProvisionSchema(req, passwordHash)
	if err != nil {
		utils.SendErrorSchemaMessage(w, r, err, transactionId, http.StatusBadRequest)
		return
	}
	logs.Log("Tenant Namespace: ", tenantNamespace)

	signer, err := jwt.NewSignerHS(jwt.HS512, PrivateKey)
	if err != nil {
		logs.Log(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	claims := &jwt.RegisteredClaims{
		ID:        uuid.NewV4().String(),
		Audience:  []string{tenantNamespace},
		Issuer:    "POSTIT",
		Subject:   "User Login Authentication",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	b, err := signer.Sign(PrivateKey)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	logs.Log(string(b))

	builder := jwt.NewBuilder(signer)
	token, err := builder.Build(claims)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Println(token.SecureString())

	w.Header().Add("Token", token.String())
	w.Header().Add("Tenant-Namespace", tenantNamespace)
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