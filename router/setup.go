package router

import (
	"PROJ/util"

	"github.com/gofiber/fiber/v2"
)

func hello(c *fiber.Ctx) error {
	return c.SendString("Hello ChinnoH!")
}

// USER handles all the user routes
// USER จัดการเส้นทางทั้งหมดของผู้ใช้งาน
var USER fiber.Router

// SetupRoutes setups all the Routes
func SetupRoutes(app *fiber.App) {
	api := app.Group("/")
	USER := app.Group("/user")

	api.Get("/", hello)

	USER.Post("/signup", CreateUser)
	USER.Post("/signin", LoginUser)
	USER.Get("/get-access-token", GetAccessToken)

	// privUser handles all the private user routes that requires authentication
	privUser := USER.Group("/private")
	privUser.Use(util.SecureAuth())
	privUser.Get("/user", GetUserData)
}
