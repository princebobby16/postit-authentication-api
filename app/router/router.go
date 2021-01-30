package router

import (
	"github.com/gorilla/mux"
	"net/http"
	"postit-authentication-server/app/controller"
	"postit-authentication-server/app/controller/auth"
	"postit-authentication-server/app/controller/user"
)

//Route Create a single route object
type Route struct {
	Name    string
	Path    string
	Method  string
	Handler http.HandlerFunc
}

//Routes Create an object of different routes
type Routes []Route

// InitRoutes Set up routes
func InitRoutes() *mux.Router {

	router := mux.NewRouter()

	routes := Routes{
		// health check
		Route{
			Name:    "Health Check",
			Path:    "/",
			Method:  http.MethodGet,
			Handler: controller.HealthCheckHandler,
		},

		// Login
		Route{
			Name: 	"Login",
			Path: 	"/login",
			Method: http.MethodPost,
			Handler: auth.Login,
		},
		Route{
			Name:    "Delete User",
			Path:    "/user/delete",
			Method:  http.MethodGet,
			Handler: user.DeleteUser,
		},
		// Refresh Token
		Route{
			Name: "Resources",
			Path: "/refresh-token",
			Method: http.MethodPost,
			Handler: auth.RefreshToken,
		},
		Route{
			Name: "Resources",
			Path: "/a",
			Method: http.MethodPost,
			Handler: auth.Test,
		},
		Route{
			Name: "SignUp",
			Path: "/signup",
			Method: http.MethodPost,
			Handler: auth.SignUp,
		},
		Route{
			Name: "ValidateToken",
			Path: "/validate",
			Method: http.MethodPost,
			Handler: auth.ValidateToken,
		},
	}

	for _, route := range routes {
		var handler http.Handler

		handler = route.Handler

		router.Name(route.Name).
			Methods(route.Method).
			Path(route.Path).
			Handler(handler)
	}

	return router
}
