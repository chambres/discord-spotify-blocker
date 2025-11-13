package main

import "log"

func main() {
	log.Println("Starting proxy...")

	// Calls a function that only exists on Windows builds
	startProxy()
}
