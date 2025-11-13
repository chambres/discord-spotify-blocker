//go:build windows
// +build windows

package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/getlantern/systray"
)

const proxyAddress = "127.0.0.1:8880"

// Returns true if ca.pem is in Trusted Root Certification Authorities
func IsCARootInstalled(caPath string) (bool, error) {
	// Read CA file and compute SHA1 fingerprint (hex uppercase)
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return false, fmt.Errorf("cannot read CA file: %w", err)
	}
	block, _ := pem.Decode(caBytes)
	if block == nil {
		return false, fmt.Errorf("invalid PEM in CA file")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("cannot parse CA: %w", err)
	}
	caSHA1 := sha1.Sum(caCert.Raw)
	fingerprint := fmt.Sprintf("%X", caSHA1)

	// Use certutil to list certificates in the Root store and look for the fingerprint.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "certutil", "-store", "Root")
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return false, fmt.Errorf("certutil timed out")
	}
	if err != nil {
		return false, fmt.Errorf("certutil failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	outStr := strings.ToUpper(string(out))
	if strings.Contains(outStr, fingerprint) {
		return true, nil
	}
	return false, nil
}

// Load your existing "My Local Proxy CA"
func mustLoadCA() tls.Certificate {
	certPEM, err := os.ReadFile("ca.pem")
	if err != nil {
		log.Fatalf("failed to read ca.pem: %v", err)
	}
	keyPEM, err := os.ReadFile("ca.key")
	if err != nil {
		log.Fatalf("failed to read ca.key: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("failed to parse key pair: %v", err)
	}
	return cert
}

const iconBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII="

// showMessageBox displays a blocking modal message box using PowerShell MessageBox.
// This avoids unsafe code while ensuring a modal dialog on Windows.
func showMessageBox(title, message string) {
	// Escape single quotes for PowerShell single-quoted string
	esc := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	ps := fmt.Sprintf("Add-Type -AssemblyName System.Windows.Forms;[System.Windows.Forms.MessageBox]::Show('%s','%s',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error)", esc(message), esc(title))
	cmd := exec.Command("powershell", "-NoProfile", "-Command", ps)
	// Run and wait until user closes the dialog
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("showMessageBox failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
}

func install_cert() error {
	// certutil -addstore -f Root ca.pem
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "certutil", "-addstore", "-f", "Root", "ca.pem")
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("certutil timed out")
	}
	if err != nil {
		return fmt.Errorf("certutil failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func enable_proxy_with_regedit() error {
	// 	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" ^
	//  /v ProxyEnable /t REG_DWORD /d 1 /f

	// reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" ^
	//  /v ProxyServer /t REG_SZ /d "127.0.0.1:8880" /f

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd1 := exec.CommandContext(ctx, "reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f")
	out1, err1 := cmd1.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("reg add ProxyEnable timed out")
	}
	if err1 != nil {
		return fmt.Errorf("reg add ProxyEnable failed: %w: %s", err1, strings.TrimSpace(string(out1)))
	}

	cmd2 := exec.CommandContext(ctx, "reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyServer", "/t", "REG_SZ", "/d", proxyAddress, "/f")
	out2, err2 := cmd2.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("reg add ProxyServer timed out")
	}
	if err2 != nil {
		return fmt.Errorf("reg add ProxyServer failed: %w: %s", err2, strings.TrimSpace(string(out2)))
	}
	return nil
}

func disable_proxy_with_regedit() error {
	// reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" ^
	//  /v ProxyEnable /t REG_DWORD /d 0 /f
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f")
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("reg add ProxyEnable (disable) timed out")
	}
	if err != nil {
		return fmt.Errorf("reg add ProxyEnable (disable) failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func startProxy() {

	//if not windows, exit
	if runtime.GOOS != "windows" {
		log.Println("This program is only supported on Windows.")
		return
	}

	// Ensure CA exists (generate if missing)
	if _, err := os.Stat("ca.pem"); os.IsNotExist(err) {
		log.Println("ca.pem not found — generating CA files")
		generate()
	}

	// make sure CA is installed in Trusted Root Certification Authorities
	if installed, err := IsCARootInstalled("ca.pem"); err != nil {
		// If cert check failed, show a modal so the user notices and then exit.
		// If the error code is 0x80070005 (access denied), suggest running as admin.
		if errno, ok := err.(syscall.Errno); ok && errno == 0x80070005 {
			msg := fmt.Sprintf("failed to check if CA is installed: %v (access denied, try running as administrator)", err)
			log.Print(msg)
			showMessageBox("Proxy setup error", msg)
			return
		} else {
			msg := fmt.Sprintf("failed to check if CA is installed: %v", err)
			log.Print(msg)
			showMessageBox("Proxy setup error", msg)
			return
		}
	} else if !installed {
		log.Println("CA not found in Trusted Root Certification Authorities — installing")
		if err := install_cert(); err != nil {
			msg := fmt.Sprintf("failed to install CA: %v", err)
			log.Print(msg)
			showMessageBox("Proxy setup error", msg)
			// exit program
			return
		} else {
			log.Println("CA installed successfully")
		}
	}

	//Override goproxy's default CA with *your* CA
	goproxy.GoproxyCa = mustLoadCA()

	proxy := goproxy.NewProxyHttpServer()
	// Completely silence goproxy: disable verbose and route its logger to discard.
	proxy.Verbose = false // set to true for debugging
	proxy.Logger = log.New(io.Discard, "", 0)

	// MITM all HTTPS
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	//regedit for proxy on
	if err := enable_proxy_with_regedit(); err != nil {
		log.Printf("failed to enable proxy via regedit: %v", err)

		disable_proxy_with_regedit()
		return

	} else {
		log.Println("system proxy enabled (" + proxyAddress + ")")
	}

	// Ensure we disable the system proxy when the program exits or is interrupted.
	defer func() {
		if err := disable_proxy_with_regedit(); err != nil {
			log.Printf("failed to disable proxy on exit: %v", err)
		} else {
			log.Println("system proxy disabled")
		}
	}()

	// Rewrite Spotify pause → play
	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			// For debugging (only log when verbose enabled)
			if proxy.Verbose {
				ctx.Logf("REQ: %s %s%s (host=%s)", r.Method, r.URL.Scheme, r.URL.Path, r.Host)
			}

			if (r.URL.Scheme == "https" || r.URL.Scheme == "http") &&
				r.Host == "api.spotify.com" &&
				r.URL.Path == "/v1/me/player/pause" {

				log.Println("Rewriting Spotify pause -> play")
				r.URL.Path = "/v1/me/player/play"
				r.URL.RawPath = ""
			}

			return r, nil
		},
	)

	addr := proxyAddress
	log.Println("Starting goproxy with custom CA on", addr)

	srv := &http.Server{Addr: addr, Handler: proxy}

	// Run server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		} else {
			serverErr <- nil
		}
	}()

	// Handle OS signals: quit the systray (which will trigger cleanup) when interrupted.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		systray.Quit()
	}()

	// Start the system tray. onExit will run cleanup (shutdown server and disable proxy).
	systray.Run(func() {
		// onReady
		// set icon (decode tiny PNG) and show status
		if data, err := base64.StdEncoding.DecodeString(iconBase64); err == nil {
			// Avoid setting a PNG icon on Windows because systray expects ICO on Windows
			// and passing PNG there can cause spurious errors in the systray internals.
			if runtime.GOOS == "windows" {
				log.Println("skipping SetIcon on Windows (embedded icon is PNG); provide an ICO if you want an icon")
			} else {
				systray.SetIcon(data)
			}
		}
		systray.SetTooltip("Proxy on")
		mStatus := systray.AddMenuItem("Proxy on", "Proxy is running")
		mQuit := systray.AddMenuItem("Quit", "Quit the application")

		// update status item (read-only) -- ensure it exists and is not clickable
		go func() {
			for {
				select {
				case <-mQuit.ClickedCh:
					systray.Quit()
					return
				case err := <-serverErr:
					if err != nil {
						// Show modal with the error, then quit
						showMessageBox("Proxy error", err.Error())
					}
					systray.Quit()
					return
				}
			}
		}()

		// disable click on status: keep it updated textually
		_ = mStatus
	}, func() {
		// onExit: perform cleanup
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if srv != nil {
			if err := srv.Shutdown(ctx); err != nil {
				log.Printf("server shutdown error: %v", err)
			}
		}
		if err := disable_proxy_with_regedit(); err != nil {
			log.Printf("failed to disable proxy on exit: %v", err)
		} else {
			log.Println("system proxy disabled")
		}
	})

	log.Println("exiting")
}
