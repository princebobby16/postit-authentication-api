package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"github.com/gorilla/handlers"
	_ "github.com/joho/godotenv/autoload"
	"golang.org/x/net/context"
	"net/http"
	"os"
	"os/signal"
	"postit-authentication-server/app/middlewares"
	"postit-authentication-server/app/router"
	"postit-authentication-server/db"
	"postit-authentication-server/pkg/logs"
	"time"
)

func init() {
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		_ = logs.Logger.Error(err)
		return
	}

	//publicKey := key.PublicKey

	//_ = saveGobKey("private.key", key)
	_ = savePEMKey("private.pem", key)

	//_ = saveGobKey("public.key", publicKey)
	//_ = savePublicPEMKey("public.pem", publicKey)
}

func main() {

	var wait time.Duration
	flag.DurationVar(&wait, "graceful-timeout", time.Second*15, "the duration for which the server gracefully wait for existing connections to finish - e.g. 15s or 1m")
	flag.Parse()

	// Is this better?
	db.Connect()

	r := router.InitRoutes()

	origins := handlers.AllowedOrigins([]string{/*"https://postit-ui.herokuapp.com"*/ "*"})
	exposedHeaders := handlers.ExposedHeaders([]string{"Token", "Tenant-Namespace"})
	headers := handlers.AllowedHeaders([]string{
		"Content-Type",
		"Content-Length",
		"Content-Event-Type",
		"X-Requested-With",
		"Accept-Encoding",
		"Accept",
		"Authorization",
		"Access-Control-Allow-Origin",
		"User-Agent",
		"tenant-namespace",
		"trace-id",
	})

	methods := handlers.AllowedMethods([]string{
		http.MethodPost,
		http.MethodGet,
		http.MethodPut,
		http.MethodDelete,
		http.MethodOptions,
		http.MethodPut,
	})

	var port string
	port = os.Getenv("PORT")
	if port == "" {
		logs.Logger.Warn("Defaulting to port 3576")
		port = "3576"
	}

	address := ":" + port

	server := &http.Server {
		Addr: address,
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      handlers.CORS(origins, headers, exposedHeaders, methods)(r), // Pass our instance of gorilla/mux in.
	}

	r.Use(middlewares.JSONMiddleware)

	defer db.Disconnect()
	// Run our server in a goroutine so that it doesn't block.
	go func() {
		logs.Logger.Info("Server running on port", address)
		if err := server.ListenAndServe(); err != nil {
			logs.Logger.Error(err)
		}
	}()

	channel := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.

	signal.Notify(channel, os.Interrupt)
	// Block until we receive our signal.
	<-channel

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	_ = server.Shutdown(ctx)

	// Optionally, you could run server.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	logs.Logger.Warn("shutting down")
	os.Exit(0)
}

//func saveGobKey(fileName string, key interface{}) error {
//	outFile, err := os.Create(fileName)
//	if err != nil {
//		return err
//	}
//	defer outFile.Close()
//
//	encoder := gob.NewEncoder(outFile)
//	err = encoder.Encode(key)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}

func savePEMKey(fileName string, key *rsa.PrivateKey)  error {

	if _, err := os.Stat(fileName); !os.IsNotExist(err) {
		return nil
	}

	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	if err != nil {
		return err
	}

	return nil
}

//func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) error {
//	asn1Bytes, err := asn1.Marshal(pubkey)
//	if err != nil {
//		return err
//	}
//
//	var pemkey = &pem.Block{
//		Type:  "PUBLIC KEY",
//		Bytes: asn1Bytes,
//	}
//
//	pemfile, err := os.Create(fileName)
//	if err != nil {
//		return err
//	}
//	defer pemfile.Close()
//
//	err = pem.Encode(pemfile, pemkey)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}