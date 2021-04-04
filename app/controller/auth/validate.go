package auth

import (
	"encoding/json"
	"github.com/cristalhq/jwt"
	"github.com/twinj/uuid"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/logs"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/models"
	"net/http"
	"strings"
	"time"
)

func ValidateToken(w http.ResponseWriter, r *http.Request) {
	// Generate a transaction Id for this particular transaction
	transactionID := uuid.NewV4().String()
	// get the trace-id
	traceId := r.Header.Get("trace-id")
	logs.Logger.Info("Trace Id: ", traceId)
	tokenHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
	tokenString := tokenHeader[1]
	logs.Logger.Info("Token: ", tokenString)

	// create a  new verifier to verify the token
	verifier, err := jwt.NewHS512(PrivateKey)
	if err != nil {
		logs.Logger.Info(err)
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
	token, err := jwt.Parse([]byte(tokenString))
	if err != nil {
		logs.Logger.Info(err)
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
		logs.Logger.Info(err)
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

	logs.Logger.Info("Token is valid")
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
