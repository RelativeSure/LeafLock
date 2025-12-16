package main

import (
	"embed"
	"github.com/gofiber/fiber/v2"
	"html/template"
)

//go:embed docs/openapi.json
var openAPIFS embed.FS

// AdminOnlyFromEnv has been removed - admin access is now managed through Clerk
// This function returns a handler that denies all access for backward compatibility
func AdminOnlyFromEnv() fiber.Handler {
	return func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Bootstrap admin access removed - use Clerk authentication",
		})
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
