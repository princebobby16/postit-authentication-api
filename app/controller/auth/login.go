package auth

import (
	"encoding/json"
	"github.com/cristalhq/jwt"
	"github.com/lib/pq"
	"github.com/twinj/uuid"
	"gitlab.com/pbobby001/postit-authentication-server/db"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/logs"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/models"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/utils"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
	"time"
)

var (
	PrivateKey []byte
)

func init() {
	data, err := ioutil.ReadFile("private.pem")
	if err != nil {
		_ = logs.Logger.Error(err)
	}
	PrivateKey = data
}

func Login(w http.ResponseWriter, r *http.Request) {

	// Transaction Id
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
	logs.Logger.Info("Headers TraceId: ", traceId)

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusBadRequest)
		return
	}
	defer func() {
		err = r.Body.Close()
		if err != nil {
			logs.Logger.Info(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}()

	logs.Logger.Info("Request Object: ", string(body))

	var loginRequest models.LoginCredentials

	err = json.Unmarshal(body, &loginRequest)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusBadRequest)
		return
	}

	logs.Logger.Info("Decoded Request Object: ", loginRequest)

	var storedPasswordHash []byte

	companyId := ""

	query := `SELECT login_id, password FROM postit_auth.login WHERE username = $1`
	err = db.Connection.QueryRow(query, loginRequest.Username).Scan(&companyId, &storedPasswordHash)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Invalid username", transactionId, http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword(storedPasswordHash, []byte(loginRequest.Password))
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Invalid password", transactionId, http.StatusInternalServerError)
		return
	}

	var companyDetails models.SignUpRequest
	query = `SELECT * FROM postit_auth.company WHERE company_id = $1`
	err = db.Connection.QueryRow(query, companyId).Scan(
		&companyDetails.CompanyId,
		&companyDetails.CompanyName,
		&companyDetails.CompanyEmail,
		pq.Array(&companyDetails.CompanyContactNumber),
		&companyDetails.GhanaPostAddress,
		&companyDetails.CompanyAddress,
		&companyDetails.CompanyWebsite,
		&companyDetails.AdminFirstName,
		&companyDetails.AdminLastName,
		&companyDetails.Namespace,
		&companyDetails.CreatedAt,
		&companyDetails.UpdatedAt,
	)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusInternalServerError)
		return
	}
	logs.Logger.Info("Company Details: ", companyDetails)

	tenantNamespace, err := utils.GenerateSchemaName(companyDetails.CompanyName)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusInternalServerError)
		return
	}
	logs.Logger.Info("Tenant Namespace: ", tenantNamespace)

	signer, err := jwt.NewHS512(PrivateKey)
	if err != nil {
		_ = logs.Logger.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	claims := &jwt.StandardClaims {
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

	w.Header().Add("token", string(token.Raw()))
	w.Header().Add("tenant-namespace", tenantNamespace)
	err = json.NewEncoder(w).Encode(&models.LoginResponseData{
		CompanyData: companyDetails,
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
