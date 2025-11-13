//go:build !windows
// +build !windows

package main

func startProxy() {
	panic("This program only runs on Windows.")
}
