package access

import (
	"encoding/json"
	"github.com/twinj/uuid"
	"io/ioutil"
	"log"
	"net/http"
	"postit-api/cmd/postit/db"
	"postit-api/cmd/postit/pkg"
	"time"
)

func HandleGetFacebookAccessToken(w http.ResponseWriter, r *http.Request) {
	// Generate id for this transaction
	transactionId := uuid.NewV4()
	log.Println("Transaction Id: ", transactionId)

	// Validate the headers
	var headers, err = pkg.ValidateHeaders(r)
	if err != nil {
		log.Println(err)
		return
	}

	traceId := headers["trace-id"]
	log.Println("Trace Id: ", traceId)
	tenantNamespace := headers["tenant-namespace"]
	log.Println("Tenant Namespace: ", tenantNamespace)

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Request body: ", string(body))

	var request pkg.AccessTokenRequest
	err = json.Unmarshal(body, &request)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Request Object: ", request)

	//build the query
	query := "INSERT INTO " + tenantNamespace + ".fb_access () VALUES ()"
	result, err := db.Connection.Exec(query)
	if err != nil {
		log.Println(err)
		return
	}

	id, _ := result.LastInsertId()
	log.Println("Last Insert Id: ", id)

	response := &pkg.StandardResponse{
		Data: pkg.Data{
			Id:        "",
			UiMessage: "Logged In successfully",
		},
		Meta: pkg.Meta{
			Timestamp:     time.Now(),
			TransactionId: transactionId.String(),
			TraceId:       traceId,
			Status:        "SUCCESS",
		},
	}
	_ = json.NewEncoder(w).Encode(response)
}
