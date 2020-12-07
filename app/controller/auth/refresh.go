package auth

import (
	"encoding/json"
	"github.com/cristalhq/jwt"
	"github.com/twinj/uuid"
	"io/ioutil"
	"log"
	"net/http"
	"postit-authentication-server/pkg/logs"
	"postit-authentication-server/pkg/models"
	"postit-authentication-server/pkg/utils"
	"time"
)

type token struct {
	Token string 			`json:"token"`
}

func RefreshToken(w http.ResponseWriter, r *http.Request) {

	// Transaction Id
	transactionId := uuid.NewV4()
	logs.Log("TransactionId: ", transactionId)

	headers, err := utils.ValidateHeaders(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		logs.Log(err)
		_ = json.NewEncoder(w).Encode(models.StandardErrorResponse {
			Message: "Something went wrong. Contact Admin",
			Meta:    models.MetaData{
				TraceId:       headers["trace-id"],
				TransactionId: transactionId.String(),
				TimeStamp:     time.Now(),
				Status:        "FAIL",
			},
		})
		return
	}

	//Get the relevant headers
	traceId := headers["trace-id"]

	// Logging the headers
	logs.Log("Headers => TraceId: %s", traceId)

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		logs.Log(err)
		_ = json.NewEncoder(w).Encode(models.StandardErrorResponse{
			Message: "Something went wrong. Contact Admin",
			Meta:    models.MetaData{
				TraceId:       headers["trace-id"],
				TransactionId: transactionId.String(),
				TimeStamp:     time.Now(),
				Status:        "FAIL",
			},
		})
		return
	}
	defer r.Body.Close()

	var req token
	logs.Log("Request Object: ", string(body))
	err = json.Unmarshal(body, &req)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong! Contact Admin", transactionId, http.StatusBadRequest)
		return
	}
	verifier,err := jwt.NewVerifierHS(jwt.HS512, PrivateKey)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong! Contact Admin", transactionId, http.StatusBadRequest)
		return
	}
	oldToken, err := jwt.Parse([]byte(req.Token), verifier)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong! Contact Admin", transactionId, http.StatusBadRequest)
		return
	}

	var claims jwt.RegisteredClaims
	err = json.Unmarshal(oldToken.RawClaims(), &claims)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong! Contact Admin", transactionId, http.StatusBadRequest)
		return
	}
	claims.IssuedAt = jwt.NewNumericDate(time.Now())
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(10 * time.Minute))

	log.Println(claims)

}
