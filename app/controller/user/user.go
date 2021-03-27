package user

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/twinj/uuid"
	"gitlab.com/pbobby001/postit-authentication-server/db"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/logs"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/models"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/utils"
	"log"
	"net/http"
	"os"
	"time"
)

func DeleteUser(w http.ResponseWriter, r *http.Request) {

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

	id := r.URL.Query().Get("user_id")
	logs.Logger.Info("User id ", id)

	tenantNamespace := r.Header.Get("tenant-namespace")
	logs.Logger.Info(tenantNamespace)

	query := fmt.Sprint("DELETE FROM postit_auth.company WHERE user_id = $1;")
	logs.Logger.Info(query)

	_, err = db.Connection.Exec(query, id)
	if err != nil {
		_ = logs.Logger.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	query = fmt.Sprintf("DROP SCHEMA %s CASCADE;", tenantNamespace)
	connection, err := sql.Open("postgres", os.Getenv("POSTIT_DATABASE_URL"))
	if err != nil {
		_ = logs.Logger.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logs.Logger.Info(query)

	_, err = connection.Exec(query)
	if err != nil {
		_ = logs.Logger.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(&models.StandardErrorResponse{
		Message: "USER DELETED SUCCESSFULLY",
		Meta:    models.MetaData{
			TraceId:       traceId,
			TransactionId: transactionId.String(),
			TimeStamp:     time.Now(),
			Status:        "SUCCESS",
		},
	})

}
