package auth

import (
	"encoding/json"
	"github.com/cristalhq/jwt"
	"github.com/twinj/uuid"
	"log"
	"net/http"
	"postit-authentication-server/pkg/logs"
	"postit-authentication-server/pkg/utils"
	"time"
)

func RefreshToken(w http.ResponseWriter, r *http.Request) {

	// Transaction Id
	transactionId := uuid.NewV4()
	logs.Logger.Info("TransactionId: ", transactionId)

	// Get the token from the header
	token := r.Header.Get("token")
	logs.Logger.Info("Token:", token)

	verifier, err := jwt.NewVerifierHS(jwt.HS512, PrivateKey)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong! Contact Admin", transactionId, http.StatusBadRequest)
		return
	}
	oldToken, err := jwt.Parse([]byte(token), verifier)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong! Contact Admin", transactionId, http.StatusBadRequest)
		return
	}

	var claims jwt.RegisteredClaims
	err = json.Unmarshal(oldToken.RawClaims(), &claims)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong! Contact Admin", transactionId, http.StatusBadRequest)
		return
	}

	newClaims := &jwt.RegisteredClaims{
		ID:        uuid.NewV4().String(),
		Audience:  claims.Audience,
		Issuer:    "PostIt",
		Subject:   "User refresh token",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(20 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	logs.Logger.Info("old audience:", claims.Audience)
	logs.Logger.Info("new audience: ", newClaims.Audience)
	signer, err := jwt.NewSignerHS(jwt.HS512, PrivateKey)
	if err != nil {
		logs.Logger.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	b, err := signer.Sign(PrivateKey)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	logs.Logger.Info(string(b))

	builder := jwt.NewBuilder(signer)
	newToken, err := builder.Build(newClaims)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Println(newToken.SecureString())
	w.Header().Add("refresh-token", newToken.String())
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("token created"))
}
