package auth

import (
	"encoding/json"
	"github.com/twinj/uuid"
	"io/ioutil"
	"net/http"
	"postit-authentication-server/pkg/logs"
	"postit-authentication-server/pkg/models"
	"postit-authentication-server/pkg/utils"
	"time"
)

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

	logs.Log("Request Object: ", string(body))
}
