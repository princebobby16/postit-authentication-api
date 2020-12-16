package auth

import (
	"encoding/json"
	"github.com/cristalhq/jwt"
	"github.com/twinj/uuid"
	"net/http"
	"postit-authentication-server/pkg/logs"
	"postit-authentication-server/pkg/models"
	"strings"
	"time"
)

func ValidateToken(w http.ResponseWriter, r *http.Request) {
	// Generate a transaction Id for this particular transaction
	transactionID := uuid.NewV4().String()
	// get the trace-id
	traceId := r.Header.Get("trace-id")
	logs.Log("Trace Id: ", traceId)
	tokenHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
	tokenString := tokenHeader[1]
	logs.Log("Token: ", tokenString)

	// create a  new verifier to verify the token
	verifier, err := jwt.NewVerifierHS(jwt.HS512, PrivateKey)
	if err != nil {
		logs.Log(err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(struct {
			Message string 				`json:"message"`
			Meta models.MetaData		`json:"meta"`
		}{
			Message: "Something went wrong!",
			Meta: models.MetaData{
				TraceId:       traceId,
				TransactionId: transactionID,
				TimeStamp:     time.Now(),
				Status:        "UNAUTHORIZED",
			},
		})
	}

	// use the verifier to parse the token
	token, err := jwt.ParseString(tokenString, verifier)
	if err != nil {
		logs.Log(err)
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(struct {
			Message string 				`json:"message"`
			Meta models.MetaData		`json:"meta"`
		}{
			Message: "Malformed Token",
			Meta: models.MetaData{
				TraceId:       traceId,
				TransactionId: transactionID,
				TimeStamp:     time.Now(),
				Status:        "UNAUTHORIZED",
			},
		})
	}

	// Compare the token Payload with its signature
	err = verifier.Verify(token.Payload(), token.Signature())
	if err != nil {
		logs.Log(err)
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(struct {
			Message string 				`json:"message"`
			Meta models.MetaData		`json:"meta"`
		}{
			Message: "Token is invalid",
			Meta: models.MetaData{
				TraceId:       traceId,
				TransactionId: transactionID,
				TimeStamp:     time.Now(),
				Status:        "UNAUTHORIZED",
			},
		})
	}

	logs.Log("Token is valid")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(struct {
		Message string 				`json:"message"`
		Meta models.MetaData		`json:"meta"`
	}{
		Message: "Token is valid",
		Meta: models.MetaData{
			TraceId:       traceId,
			TransactionId: transactionID,
			TimeStamp:     time.Now(),
			Status:        "SUCCESS",
		},
	})
}
