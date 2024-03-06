package main

import (
	"os"

	"github.com/yinxulai/lookup-dns-ip/packages/dnsserver"
	"github.com/yinxulai/lookup-dns-ip/packages/httpserver"
)

func main() {
	domain := os.Getenv("DOMAIN")
	go dnsserver.StartServer(domain, 53)
	httpserver.StartServer(domain, 53)
}
