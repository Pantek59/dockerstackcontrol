// Package web embeds the HTML templates and static assets served by
// stackctl. Everything is compiled into the binary: no external fonts,
// scripts or images, no build step.
package web

import "embed"

// TemplatesFS holds the html/template files (layout plus one definition file
// per page).
//
//go:embed templates/*.html
var TemplatesFS embed.FS

// StaticFS holds app.js, style.css and the favicon under static/.
//
//go:embed static
var StaticFS embed.FS
