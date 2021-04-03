package utils

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"github.com/twinj/uuid"
	"gitlab.com/pbobby001/postit-authentication-server/db"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/logs"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/models"
	"net/http"
	"os"
	"strings"
	"time"
)

/* ValidateHeaders is a function used to make sure that the required  headers are sent to the API
It takes the http request and extracts the headers from it and returns a map of the needed headers
and an error. Other headers are essentially ignored.*/
func ValidateHeaders(r *http.Request) (map[string]string, error) {
	//Group the headers
	receivedHeaders := make(map[string]string)
	requiredHeaders := []string{"trace-id"}

	for _, header := range requiredHeaders {
		value := r.Header.Get(header)
		if value != "" {
			receivedHeaders[header] = value
		} else if value == "" {
			return nil, errors.New("Required header: " + header + " not found")
		} else {
			return nil, errors.New("no headers received be sure to send some headers")
		}
	}

	return receivedHeaders, nil
}

/* SendErrorMessage is a function util used to efficiently send error messages. It takes quite a
few parameters */
func SendErrorMessage(w http.ResponseWriter, r *http.Request, err error, message string, transactionId uuid.UUID, statusHeader int) {
	w.WriteHeader(statusHeader)
	logs.Logger.Info(err)
	_ = json.NewEncoder(w).Encode(models.StandardErrorResponse{
		Message: message,
		Meta: models.MetaData{
			TraceId:       r.Header.Get("trace-id"),
			TransactionId: transactionId.String(),
			TimeStamp:     time.Now(),
			Status:        "FAIL",
		},
	})
	return
}

func SendErrorSchemaMessage(w http.ResponseWriter, r *http.Request, err error, transactionId uuid.UUID, statusHeader int) {
	w.WriteHeader(statusHeader)
	logs.Logger.Info(err)
	_ = json.NewEncoder(w).Encode(models.StandardErrorResponse{
		Message: err.Error(),
		Meta: models.MetaData{
			TraceId:       r.Header.Get("trace-id"),
			TransactionId: transactionId.String(),
			TimeStamp:     time.Now(),
			Status:        "FAIL",
		},
	})
	return
}

func GenerateSchemaName(name string) (string, error) {
	var namespace string
	newS := strings.Split(strings.ToLower(name), " ")
	namespace = strings.Join(newS, "_")
	logs.Logger.Info(namespace)
	return namespace, nil
}

func ProvisionSchema(request models.SignUpRequest, passwordHash []byte) (string, error) {
	var query string
	// New db connection
	connection, err := sql.Open("postgres", os.Getenv("POSTIT_DATABASE_URL"))
	if err != nil {
		return "", err
	}
	// generate tenantNamespace
	tenantNamespace, err := GenerateSchemaName(request.CompanyName)
	if err != nil {
		return "", err
	}
	logs.Logger.Info(tenantNamespace)

	// create schema
	query = fmt.Sprintf("CREATE SCHEMA %s;", tenantNamespace)
	logs.Logger.Info(query)
	_, err = connection.Exec(query)
	if err != nil {
		return "", errors.New("company already exists")
	}

	// create tables
	query = fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %s.post("+
			"post_id uuid UNIQUE NOT NULL, "+
			"facebook_post_id character varying(200), "+
			"post_message text NOT NULL, "+
			"post_images bytea[], "+
			"image_paths character varying(200), "+
			"hash_tags text[], "+
			"post_status boolean NOT NULL, "+
			"scheduled boolean NOT NULL, "+
			"post_priority boolean NOT NULL, "+
			"created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP, "+
			"updated_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP, "+
			"PRIMARY KEY (post_id)); "+
			"CREATE TABLE IF NOT EXISTS %s.schedule("+
			" schedule_id uuid UNIQUE NOT NULL, "+
			"schedule_title character varying(200), "+
			"post_to_feed boolean NOT NULL, "+
			"schedule_from timestamp with time zone NOT NULL, "+
			"schedule_to timestamp with time zone NOT NULL, "+
			"post_ids character varying(200)[] NOT NULL, "+
			"duration_per_post float NOT NULL, "+
			"facebook character varying(200)[] NOT NULL, "+
			"twitter character varying(200)[] NOT NULL, "+
			"linked_in character varying(200)[] NOT NULL, "+
			"is_due boolean, "+
			"created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP, "+
			"updated_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP, "+
			"PRIMARY KEY(schedule_id));"+
			"CREATE TABLE IF NOT EXISTS %s.application_info("+
			"application_uuid uuid UNIQUE NOT NULL, "+
			"application_name character varying (200) NOT NULL, "+
			"application_id character varying(200) UNIQUE NOT NULL, "+
			"application_secret character varying (200) NOT NULL, "+
			"application_url character varying (200) NOT NULL, "+
			"user_access_token text NOT NULL, "+
			"expires_in integer NOT NULL, "+
			"user_name character varying (200) UNIQUE NOT NULL, "+
			"user_id character varying (200) UNIQUE NOT NULL, "+
			"created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP, "+
			"updated_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP, "+
			"PRIMARY KEY(application_uuid));",
		tenantNamespace, tenantNamespace, tenantNamespace)
	_, err = connection.Exec(query)
	if err != nil {
		return "", err
	}

	companyId := uuid.NewV4()
	query = `INSERT INTO postit_auth.company (company_id,admin_first_name,admin_last_name,company_name,company_email,company_phone_numbers,company_address,company_website,company_ghana_post_address,namespace) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	_, err = db.Connection.Exec(query,
		&companyId,
		&request.AdminFirstName,
		&request.AdminLastName,
		&request.CompanyName,
		&request.CompanyEmail,
		pq.Array(&request.CompanyContactNumber),
		&request.CompanyAddress,
		&request.CompanyWebsite,
		&request.GhanaPostAddress,
		&tenantNamespace,
	)
	if err != nil {
		query := fmt.Sprintf("DROP SCHEMA %s CASCADE;", tenantNamespace)
		_, newErr := connection.Exec(query)
		if newErr != nil {
			logs.Logger.Info(err)
			return "", errors.New("unable to reverse transaction")
		}
		return "", errors.New("company already exists")
	}
	request.CompanyId = companyId.String()
	request.Password = ""

	logs.Logger.Info(query)
	query = `INSERT INTO postit_auth.login(login_id, username, password) VALUES($1,$2,$3)`
	_, err = db.Connection.Exec(query,
		&companyId,
		&request.Username,
		passwordHash,
	)
	if err != nil {
		query := fmt.Sprintf("DROP SCHEMA %s CASCADE;", tenantNamespace)
		_, err = connection.Exec(query)
		if err != nil {
			logs.Logger.Info(err)
			return "", errors.New("unable to reverse transaction")
		}
		return "", errors.New("username already exists")
	}

	logs.Logger.Info(query)

	return tenantNamespace, nil
}
