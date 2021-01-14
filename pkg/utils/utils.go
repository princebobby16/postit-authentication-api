package utils

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"github.com/twinj/uuid"
	"net/http"
	"os"
	"postit-authentication-server/db"
	"postit-authentication-server/pkg/logs"
	"postit-authentication-server/pkg/models"
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
	logs.Log(err)
	_ = json.NewEncoder(w).Encode(models.StandardErrorResponse {
		Message: message,
		Meta:    models.MetaData{
			TraceId:       r.Header.Get("trace-id"),
			TransactionId: transactionId.String(),
			TimeStamp:     time.Now(),
			Status:        "FAIL",
		},
	})
	return
}

func SendErrorSchemaMessage(w http.ResponseWriter, r *http.Request, err error, transactionId uuid.UUID, statusHeader int){
	w.WriteHeader(statusHeader)
	logs.Log(err)
	_ = json.NewEncoder(w).Encode(models.StandardErrorResponse {
		Message: err.Error(),
		Meta:    models.MetaData{
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
	logs.Log(namespace)
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
	logs.Log(tenantNamespace)

	// create schema
	query = fmt.Sprintf("CREATE SCHEMA %s", tenantNamespace)
	logs.Log(query)
	_, err = connection.Exec(query)
	if err != nil {
		return "", errors.New("Company already exists!")
	}

	// create tables
	query = fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s.post(post_id uuid UNIQUE NOT NULL, post_message text NOT NULL, post_image bytea, image_extension character varying(200), hash_tags text[], post_status boolean NOT NULL, post_priority boolean NOT NULL, created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (post_id)); CREATE TABLE IF NOT EXISTS %s.schedule( schedule_id uuid UNIQUE NOT NULL, schedule_title character varying(200), post_to_feed boolean NOT NULL, schedule_from timestamp with time zone NOT NULL, schedule_to timestamp with time zone NOT NULL, post_ids character varying(200)[] NOT NULL, duration_per_post float NOT NULL, created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (schedule_id)); CREATE TABLE IF NOT EXISTS %s.scheduled_post(scheduled_post_id uuid NOT NULL, post_id uuid NOT NULL, post_message text NOT NULL, post_image bytea, image_extension character varying(200), hash_tags text[], post_status boolean NOT NULL, post_priority boolean NOT NULL, created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS %s.application_info\n(\n    application_uuid uuid UNIQUE NOT NULL,\n    application_name character varying (200) NOT NULL,\n    application_id character varying(200) NOT NULL,\n    application_secret character varying (200) NOT NULL,\n    application_url character varying (200) NOT NULL,\n    user_access_token text,\n    expires_in integer,\n    user_name character varying (200),\n    user_id character varying (200),\n    created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,\n    updated_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,\n    PRIMARY KEY(application_uuid));", tenantNamespace, tenantNamespace, tenantNamespace, tenantNamespace)
	_, err = connection.Exec(query)
	if err != nil {
		return "", err
	}

	// create triggers
	query = fmt.Sprintf("create or replace function %s.store_schedule_data_in_scheduled_post_table_ait() returns trigger as $$\n\nDECLARE\n--     schedule vars\n    iD           uuid := NEW.schedule_id;\n    scheduleId   uuid;\n    scheduleFrom timestamp;\n    scheduleTo   timestamp;\n    postList     varchar(200)[];\n\n--     Post vars\n    postId       uuid;\n    postMessage  text;\n    postImage    bytea;\n    imageExtension character varying (200);\n    hashTags     text[];\n    postStatus boolean;\n    postPriority boolean;\n\nBEGIN\n\n--     Get the schedule data\n    SELECT schedule_id, schedule_from, schedule_to, post_ids INTO scheduleId, scheduleFrom, scheduleTo, postList FROM %s.schedule WHERE schedule_id = iD;\n--     Loop through the post array retrieved from the schedule table to get the post ids\n    FOREACH postId IN ARRAY postList\n    LOOP\n--      Use the post ids to retrieve the post info from the post table\n        SELECT post_message, post_image, image_extension, hash_tags, post_priority, post_status INTO postMessage, postImage, imageExtension, hashTags, postPriority, postStatus FROM %s.post WHERE post_id = postId;\n\n--      Store it in the scheduled data table\n        INSERT INTO %s.scheduled_post(scheduled_post_id, post_id, post_message, post_image, image_extension, hash_tags, post_status, post_priority) VALUES (scheduleId, postId, postMessage, postImage, imageExtension, hashTags, postStatus, postPriority);\n\n    END LOOP;\n\n    RETURN NEW;\n\nEND;\n$$ language plpgsql;\n\nDROP TRIGGER IF EXISTS schedule_ait ON %s.schedule;\nCREATE TRIGGER schedule_ait AFTER INSERT ON %s.schedule FOR EACH ROW EXECUTE PROCEDURE %s.store_schedule_data_in_scheduled_post_table_ait();\n-- +goose StatementEnd\n\n-- +goose StatementBegin\ncreate or replace function %s.delete_posts_from_scheduled_post_table_bdt() returns trigger as $$\n\nDECLARE\n\n    schedule_id uuid = OLD.schedule_id;\n\nBEGIN\n\n    DELETE FROM %s.scheduled_post WHERE scheduled_post_id = schedule_id;\n\n    RETURN OLD;\n\nEND;\n$$ language plpgsql;\n\nDROP TRIGGER IF EXISTS schedule_bdt ON %s.schedule;\nCREATE TRIGGER schedule_bdt BEFORE DELETE ON %s.schedule FOR EACH ROW EXECUTE PROCEDURE %s.delete_posts_from_scheduled_post_table_bdt();",
		tenantNamespace,
		tenantNamespace,
		tenantNamespace,
		tenantNamespace,
		tenantNamespace,
		tenantNamespace,
		tenantNamespace,
		tenantNamespace,
		tenantNamespace,
		tenantNamespace,
		tenantNamespace,
		tenantNamespace,
	)
	_, err = connection.Exec(query)
	if err != nil {
		return "", err
	}
	logs.Log(query)

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
			logs.Log(err)
			return "", errors.New("Something went wrong! contact admin!")
		}
		return "", errors.New("company already exists")
	}
	request.CompanyId = companyId.String()
	request.Password = ""

	logs.Log(query)
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
			logs.Log(err)
			return "", errors.New("Something went wrong! contact admin!")
		}
		return "", errors.New("Username already exists")
	}
	logs.Log(query)

	return tenantNamespace, nil
}