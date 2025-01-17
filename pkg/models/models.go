package models

import (
	"time"
)

type (
	HealthCheck struct {
		Status          string  `json:"status"`
		ApplicationName string  `json:"application_name"`
		Version         float64 `json:"version"`
		Author          string  `json:"author"`
		Email           string  `json:"email"`
		Company         string  `json:"company"`
		Owner           string  `json:"owner"`
	}

	SignUpRequest struct {
		CompanyId            string    `json:"company_id"`
		AdminFirstName       string    `json:"admin_first_name"`
		AdminLastName        string    `json:"admin_last_name"`
		Username             string    `json:"username"`
		Password             string    `json:"password"`
		CompanyName          string    `json:"company_name"`
		CompanyWebsite       string    `json:"company_website"`
		CompanyAddress       string    `json:"company_address"`
		CompanyContactNumber []string  `json:"company_contact_number"`
		CompanyEmail         string    `json:"company_email"`
		GhanaPostAddress     string    `json:"ghana_post_address"`
		Namespace            string    `json:"namespace"`
		CreatedAt            time.Time `json:"created_at"`
		UpdatedAt            time.Time `json:"updated_at"`
	}

	MiddlewareErrorMessages struct {
		Message string
	}

	CompanyDetails struct {
		CompanyName         string   `json:"company_name"`
		CompanyAddress      string   `json:"company_address"`
		CompanyEmail        string   `json:"company_email"`
		CompanyPhoneNumber  string `json:"company_phone_number"`
	}

	Profile struct {
		Username  string `json:"username"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}

	PasswordReset struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	LoginCredentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	LoginResponseData struct {
		CompanyData SignUpRequest `json:"company_data"`
		Meta        MetaData      `json:"meta"`
	}

	StandardErrorResponse struct {
		Message string   `json:"message"`
		Meta    MetaData `json:"meta"`
	}

	MetaData struct {
		TraceId       string    `json:"trace_id"`
		TransactionId string    `json:"transaction_id"`
		TimeStamp     time.Time `json:"time_stamp"`
		Status        string    `json:"status"`
	}
)
