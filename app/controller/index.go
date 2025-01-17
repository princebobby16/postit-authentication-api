package controller

import (
	"encoding/json"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/models"
	"net/http"
)

func HealthCheckHandler(w http.ResponseWriter, _ *http.Request) {
	resp := &models.HealthCheck{
		Status:          "Alive",
		ApplicationName: "PostIt Authentication Server",
		Version:         0.1,
		Author:          "Prince Bobby",
		Email:           "princebobby506@gmail.com",
		Company:         "Shiftr GH",
		Owner:           "Shiftr GH",
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
