// +heroku install .
module gitlab.com/pbobby001/postit-authentication-server
// +heroku goVersion go1.15
go 1.15

require (
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575
	github.com/cristalhq/jwt v1.2.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/joho/godotenv v1.3.0
	github.com/lib/pq v1.10.0
	github.com/prometheus/client_golang v1.10.0
	github.com/twinj/uuid v1.0.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/net v0.0.0-20210326060303-6b1517762897
)
