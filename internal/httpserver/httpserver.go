package httpserver

import (
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/yinxulai/lookup-dns-ip/internal/cache"
)

func StartServer(domain string, port int) {
	// 注册请求处理函数
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		requestHost := r.Host

		// 请求不是来自设定的域名，直接报错，不进行处理
		if !strings.HasSuffix(requestHost, domain) {
			err := fmt.Errorf("only supports access using %s domain name", domain)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// 整个流程如下
		// 用户访问 domain
		// domain 302 {random-id}.domain
		// {random-id}.domain 查询 dns-server
		// dns-server 返回 http-server ip 并记录 remote ip
		// 发起 {random-id}.domain 请求到 http-server
		// http-server 将 dns-server 记录的 remote ip 返回

		// 如果直接访问 domain
		if requestHost == domain {
			subdomain, err := generateRandomSubDomain(domain)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			protocol := "http"
			ssl := os.Getenv("SSL")
			if ssl == "true" {
				protocol = "https"
			}

			newLocation := fmt.Sprintf("%s://%s", protocol, subdomain)
			http.Redirect(w, r, newLocation, http.StatusFound)
		}

		// 如果是子域名访问
		if strings.HasSuffix(requestHost, "."+domain) {
			id, _ := strings.CutSuffix(requestHost, "."+domain)
			ip, exits := cache.GetCache(id)

			if !exits {
				if _, err := w.Write([]byte("unknown ip")); err != nil {
					log.Fatal("Write response fatal:", err)
				}
				return
			}

			if _, err := w.Write([]byte(ip)); err != nil {
				log.Fatal("Write response fatal:", err)
			}
		}
	})

	// 启动 HTTP 服务，监听在端口808
	listenAddr := fmt.Sprintf(":%d", port)
	log.Printf("HTTP server started on port %d", port)
	err := http.ListenAndServe(listenAddr, nil)
	if err != nil {
		log.Fatal("Failed to start the server:", err)
	}
}

// 生成随机的子域名
func generateRandomSubDomain(domain string) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyz"

	bytes := make([]byte, 18)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}

	return fmt.Sprintf("%s.%s", string(bytes), domain), nil
}
