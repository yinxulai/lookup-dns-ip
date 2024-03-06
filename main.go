package main

import (
	"fmt"
	"log"
	"os"

	"github.com/yinxulai/lookup-dns-ip/packages/dnsserver"
	"github.com/yinxulai/lookup-dns-ip/packages/httpserver"
)

func main() {
	domain := os.Getenv("DOMAIN")
	if domain == "" {
		err := fmt.Errorf("%s is not configured with the correct dns record", domain)
		log.Fatal(err)
		panic(err)
	}

	dnsserver.StartServer(domain, 8080)
	httpserver.StartServer(domain, 8081)
}
