// ServerManager Authenticator for Windows.
// Thin WebView2 shell around the keys.* Authenticator PWA.
package main

import (
	"os"
	"strings"

	"github.com/jchv/go-webview2"
)

func main() {
	base := os.Getenv("SERVERMANAGER_KEYS_URL")
	if base == "" {
		base = os.Getenv("SERVERMANAGER_PORTAL_URL")
	}
	if base == "" {
		base = "https://keys.vpstruelord.com"
	}
	base = strings.TrimRight(base, "/")
	url := base
	if !strings.HasSuffix(url, "auth-app.html") && !strings.HasSuffix(url, "auth-app-iphone.html") {
		url = base + "/auth-app.html"
	}

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
