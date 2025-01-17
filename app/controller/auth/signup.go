package auth

import (
	"encoding/json"
	"github.com/cristalhq/jwt"
	"github.com/twinj/uuid"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/logs"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/models"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/utils"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

const cost = 10

func SignUp(w http.ResponseWriter, r *http.Request) {
	transactionId := uuid.NewV4()
	logs.Logger.Info("TransactionId: ", transactionId)

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
	logs.Logger.Info("Request Body in bytes: ", body)
	logs.Logger.Info("Request Body as a string: ", string(body))

	var req models.SignUpRequest

	err = json.Unmarshal(body, &req)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusBadRequest)
		return
	}
	logs.Logger.Info(req)

	logs.Logger.Info("Raw Password: ", req.Password)

	// Hash the password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), cost)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Invalid Password!", transactionId, http.StatusInternalServerError)
		return
	}
	logs.Logger.Info("Hashed Password: ", passwordHash)

	// Provision schema
	tenantNamespace, err := utils.ProvisionSchema(req, passwordHash)
	if err != nil {
		utils.SendErrorSchemaMessage(w, r, err, transactionId, http.StatusBadRequest)
		return
	}
	logs.Logger.Info("Tenant Namespace: ", tenantNamespace)

	signer, err := jwt.NewHS512(PrivateKey)
	if err != nil {
		_ = logs.Logger.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	claims := &jwt.StandardClaims{
		ID:        uuid.NewV4().String(),
		Audience:  []string{"postit-audience", tenantNamespace},
		Issuer:    "POSTIT",
		Subject:   "User Login Authentication",
		ExpiresAt: jwt.Timestamp(time.Now().Add(20 * time.Minute).Unix()),
		IssuedAt:  jwt.Timestamp(time.Now().Unix()),
	}

	b, err := signer.Sign(PrivateKey)
	if err != nil {
		_ = logs.Logger.Error(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	logs.Logger.Info(string(b))

	builder := jwt.NewTokenBuilder(signer)
	token, err := builder.Build(claims)
	if err != nil {
		_ = logs.Logger.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs.Logger.Info(string(token.Raw()))

	w.Header().Add("Token", string(token.Raw()))
	w.Header().Add("Tenant-Namespace", tenantNamespace)
	err = json.NewEncoder(w).Encode(&models.LoginResponseData{
		CompanyData: req,
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
