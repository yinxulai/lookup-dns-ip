package main

import (
	"os"

	"github.com/yinxulai/lookup-dns-ip/internal/dnsserver"
	"github.com/yinxulai/lookup-dns-ip/internal/httpserver"
)

func main() {
	domain := os.Getenv("DOMAIN")
	go dnsserver.StartServer(domain, 53)
	httpserver.StartServer(domain, 53)
}
