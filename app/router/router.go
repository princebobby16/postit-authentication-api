package router

import (
	"github.com/gorilla/mux"
	"gitlab.com/pbobby001/postit-authentication-server/app/controller"
	"gitlab.com/pbobby001/postit-authentication-server/app/controller/auth"
	"gitlab.com/pbobby001/postit-authentication-server/app/controller/user"
	"net/http"
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
			Name:    "SignUp",
			Path:    "/signup",
			Method:  http.MethodPost,
			Handler: auth.SignUp,
		},
		Route{
			Name:    "ValidateToken",
			Path:    "/validate",
			Method:  http.MethodPost,
			Handler: auth.ValidateToken,
		},
		Route{
			Name:    "UserProfile",
			Path:    "/auth/profile",
			Method:  http.MethodPost,
			Handler: user.EditUserProfile,
		},
		Route{
			Name:    "ChangePassword",
			Path:    "/auth/password",
			Method:  http.MethodPost,
			Handler: user.ChangePassword,
		},
		Route{
			Name: "EditCompanyDetails",
			Path: "/auth/details",
			Method: http.MethodPost,
			Handler: user.EditCompanyDetails,
		},
	}

	for _, route := range routes {
		router.Name(route.Name).
			Methods(route.Method).
			Path(route.Path).
			Handler(route.Handler)
	}

	return router
}
