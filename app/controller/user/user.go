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
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

const cost = 10

func EditUserProfile(w http.ResponseWriter, r *http.Request) {
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
	logs.Logger.Infof("TraceId: %s", traceId)

	id := r.URL.Query().Get("company_id")
	logs.Logger.Info("Company Id: ", id)

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusBadRequest)
		return
	}

	defer func() {
		err = r.Body.Close()
		if err != nil {
			_ = logs.Logger.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}()

	logs.Logger.Info("Request Object: ", string(body))

	var profile models.Profile

	err = json.Unmarshal(body, &profile)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusBadRequest)
		return
	}

	logs.Logger.Info("Decoded Request Object: ", profile)

	query := fmt.Sprintf("UPDATE postit_auth.company SET admin_first_name = $1, admin_last_name = $2 WHERE company_id = $3")

	_, err = db.Connection.Exec(query, &profile.FirstName, &profile.LastName, &id)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusBadRequest)
		return
	}

	query = fmt.Sprintf("UPDATE postit_auth.login SET username = $1 WHERE login_id = $2")

	_, err = db.Connection.Exec(query, &profile.Username, &id)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusBadRequest)
		return
	}

	_ = json.NewEncoder(w).Encode(&models.StandardErrorResponse{
		Message: "USER PROFILE UPDATED SUCCESSFULLY",
		Meta: models.MetaData{
			TraceId:       traceId,
			TransactionId: transactionId.String(),
			TimeStamp:     time.Now(),
			Status:        "SUCCESS",
		},
	})

}

func ChangePassword(w http.ResponseWriter, r *http.Request) {
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
	logs.Logger.Infof("TraceId: %s", traceId)

	id := r.URL.Query().Get("company_id")
	logs.Logger.Info("Company Id: ", id)

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusBadRequest)
		return
	}

	defer func() {
		err = r.Body.Close()
		if err != nil {
			_ = logs.Logger.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}()

	logs.Logger.Info("Request Object: ", string(body))

	var password models.PasswordReset

	err = json.Unmarshal(body, &password)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusBadRequest)
		return
	}

	logs.Logger.Info("Decoded Request Object: ", password)

	pass := ""
	query := fmt.Sprint("SELECT password FROM postit_auth.login WHERE login_id = $1")

	err = db.Connection.QueryRow(query, id).Scan(&pass)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong. Contact Admin", transactionId, http.StatusInternalServerError)
		return
	}
	// compare old password with the one stored in the db
	err = bcrypt.CompareHashAndPassword([]byte(pass), []byte(password.OldPassword))
	if err != nil {
		utils.SendErrorMessage(w, r, err, "wrong old password", transactionId, http.StatusBadRequest)
		return
	}

	// hash the new password

	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(password.NewPassword), cost)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "something went wrong. contact admin", transactionId, http.StatusInternalServerError)
		return
	}

	query = fmt.Sprint("UPDATE postit_auth.login SET password = $1 WHERE login_id = $2")
	_, err = db.Connection.Exec(query, string(newPasswordHash), &id)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "something went wrong. contact admin", transactionId, http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(&models.StandardErrorResponse{
		Message: "PASSWORD UPDATED SUCCESSFULLY",
		Meta: models.MetaData{
			TraceId:       traceId,
			TransactionId: transactionId.String(),
			TimeStamp:     time.Now(),
			Status:        "SUCCESS",
		},
	})

}

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
	tenantNamespace := headers["tenant-namespace"]
	// Logging the headers
	log.Printf("TraceId: %s", traceId)
	logs.Logger.Info("Tenant Namespace", tenantNamespace)

	id := r.URL.Query().Get("company_id")
	logs.Logger.Info("User id ", id)

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
