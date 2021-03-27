package auth

import (
	"encoding/json"
	"gitlab.com/pbobby001/postit-authentication-server/pkg/logs"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
)

func Test(w http.ResponseWriter, r *http.Request) {
	var password = &struct {
		Password string 		`json:"password"`
	}{}
	
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logs.Logger.Info(err)
		return
	}
	
	err = json.Unmarshal(body, &password)
	if err != nil {
		logs.Logger.Info(err)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password.Password), 10)
	if err != nil {
		logs.Logger.Info(err)
		return
	}
	
	logs.Logger.Info(string(hash))

	_, _ = w.Write(hash)
}
