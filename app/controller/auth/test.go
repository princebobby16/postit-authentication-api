package auth

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
	"postit-authentication-server/pkg/logs"
)

func Test(w http.ResponseWriter, r *http.Request) {
	var password = &struct {
		Password string 		`json:"password"`
	}{}
	
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logs.Log(err)
		return
	}
	
	err = json.Unmarshal(body, &password)
	if err != nil {
		logs.Log(err)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password.Password), 10)
	if err != nil {
		logs.Log(err)
		return
	}
	
	logs.Log(string(hash))

	_, _ = w.Write(hash)
}
