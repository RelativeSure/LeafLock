package main

import (
	"embed"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"html/template"
	"os"
	"strings"
)

//go:embed docs/openapi.json
var openAPIFS embed.FS

// AdminOnlyFromEnv allows access only if the authenticated user ID is listed in ADMIN_USER_IDS (comma-separated UUIDs)
func AdminOnlyFromEnv() fiber.Handler {
	admins := strings.Split(os.Getenv("ADMIN_USER_IDS"), ",")
	for i := range admins {
		admins[i] = strings.TrimSpace(admins[i])
	}

	return func(c *fiber.Ctx) error {
		uidVal := c.Locals("user_id")
		if uidVal == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}
		uid := ""
		switch v := uidVal.(type) {
		case string:
			uid = v
		case interface{ String() string }:
			uid = v.String()
		default:
			uid = strings.TrimSpace(fmt.Sprint(v))
		}
		for _, a := range admins {
			if a != "" && a == uid {
				return c.Next()
			}
		}
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Admins only"})
	}
}

// no extra helpers

func swaggerJSONHandler(c *fiber.Ctx) error {
	data, err := openAPIFS.ReadFile("docs/openapi.json")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "openapi not found"})
	}
	c.Type("json")
	return c.Send(data)
}

func swaggerUIHandler(c *fiber.Ctx) error {
	const tpl = `<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <title>LeafLock API Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.ui = SwaggerUIBundle({
        url: '/api/v1/docs/openapi.json',
        dom_id: '#swagger-ui',
        presets: [SwaggerUIBundle.presets.apis],
        layout: 'BaseLayout'
      });
    </script>
  </body>
 </html>`
	t := template.Must(template.New("swagger").Parse(tpl))
	c.Type("html")
	return t.Execute(c, nil)
}
