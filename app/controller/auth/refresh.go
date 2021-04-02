package auth

import (
	"encoding/json"
	"github.com/cristalhq/jwt"
	"github.com/twinj/uuid"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/logs"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/utils"
	"log"
	"net/http"
	"time"
)

func RefreshToken(w http.ResponseWriter, r *http.Request) {

	// Transaction Id
	transactionId := uuid.NewV4()
	logs.Logger.Infof("TransactionId: %s", transactionId)

	// Get the token from the header
	token := r.Header.Get("token")
	logs.Logger.Info("Token:", token)


	oldToken, err := jwt.Parse([]byte(token))
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong! Contact Admin", transactionId, http.StatusBadRequest)
		return
	}

	validator := jwt.NewValidator(
		jwt.AudienceChecker(jwt.Audience{"postit-audience", r.Header.Get("tenant-namespace")}),
	)

	var claims *jwt.StandardClaims
	err = json.Unmarshal(oldToken.RawClaims(), &claims)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong! Contact Admin", transactionId, http.StatusBadRequest)
		return
	}

	err = validator.Validate(claims)
	if err != nil {
		utils.SendErrorMessage(w, r, err, "Something went wrong! Contact Admin", transactionId, http.StatusBadRequest)
		return
	}

	newClaims := &jwt.StandardClaims{
		ID:        uuid.NewV4().String(),
		Audience:  claims.Audience,
		Issuer:    "PostIt",
		Subject:   "User refresh token",
		ExpiresAt: jwt.Timestamp(time.Now().Add(20 * time.Minute).Unix()),
		IssuedAt:  jwt.Timestamp(time.Now().Unix()),
	}

	logs.Logger.Info("old audience:", claims.Audience)
	logs.Logger.Info("new audience: ", newClaims.Audience)
	signer, err := jwt.NewHS512(PrivateKey)
	if err != nil {
		_ = logs.Logger.Error(err)
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

	builder := jwt.NewTokenBuilder(signer)
	newToken, err := builder.Build(newClaims)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Println(newToken.String())
	w.Header().Add("refresh-token", newToken.String())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("token created"))
}
