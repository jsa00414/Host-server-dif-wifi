// ServerManager Authenticator for Windows.
// Thin WebView2 shell around the portal Authenticator PWA.
package main

import (
	"os"

	"github.com/jchv/go-webview2"
)

func main() {
	portal := os.Getenv("SERVERMANAGER_PORTAL_URL")
	if portal == "" {
		portal = "https://portal.vpstruelord.com"
	}
	url := portal + "/auth-app.html"

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug: false,
		WindowOptions: webview2.WindowOptions{
			Title:  "ServerManager Authenticator",
			Width:  420,
			Height: 760,
			Center: true,
		},
	})
	if w == nil {
		panic("WebView2 failed to start. Install Microsoft Edge WebView2 Runtime, then relaunch.")
	}
	defer w.Destroy()
	w.Navigate(url)
	w.Run()
}
