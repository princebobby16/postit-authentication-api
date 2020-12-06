package auth

import (
	"encoding/json"
	"github.com/cristalhq/jwt"
	"github.com/twinj/uuid"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"postit-authentication-server/db"
	"postit-authentication-server/pkg/logs"
	"postit-authentication-server/pkg/models"
	"postit-authentication-server/pkg/utils"
	"time"
)

var (
	PrivateKey []byte
)


func init() {
	data, err := ioutil.ReadFile("private.pem")
	if err != nil {
		logs.Log(err)
	}
	PrivateKey = data
	//pData, err := ioutil.ReadFile("public.pem")
	//if err != nil {
	//	logs.Log(err)
	//	return
	//}
	//PublicKey = pData
}

func Login(w http.ResponseWriter, r *http.Request) {

	// Transaction Id
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
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	logs.Log("Request Object: ", string(body))

	var loginRequest models.LoginCredentials

	err = json.Unmarshal(body, &loginRequest)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusBadRequest)
		return
	}

	logs.Log("Decoded Request Object: ", loginRequest)

	var storedPasswordHash []byte

	companyId := ""

	query := `SELECT login_id, password FROM postit_auth.login WHERE username = $1`
	err = db.Connection.QueryRow(query, loginRequest.Username).Scan(&companyId, &storedPasswordHash)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword(storedPasswordHash, []byte(loginRequest.Password))
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusInternalServerError)
		return
	}

	companyName := ""
	query = `SELECT company_name FROM postit_auth.company WHERE company_id = $1`
	err = db.Connection.QueryRow(query, companyId).Scan(&companyName)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusInternalServerError)
		return
	}

	tenantNamespace, err := utils.GenerateSchemaName(companyName)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusInternalServerError)
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

	w.Header().Add("token", token.String())
	w.Header().Add("tenant-namespace", tenantNamespace)
	err = json.NewEncoder(w).Encode(&models.LoginTokenResponse{
		Message: "Logged in successfully",
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