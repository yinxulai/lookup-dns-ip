package dnsserver

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/yinxulai/lookup-dns-ip/packages/cache"
)

func StartServer(domain string, port int) {
	serverIPs, err := net.LookupIP(domain)
	if err != nil || len(serverIPs) == 0 {
		log.Fatalf("%s is not configured with the correct dns record", domain)
	}

	// 创建UDP监听地址
	addr := net.UDPAddr{
		Port: port,
		IP:   net.ParseIP("0.0.0.0"),
	}

	// 监听UDP端口53
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatal("Error listening:", err)
	}
	defer conn.Close()

	log.Println("DNS server started on port 53")

	buffer := make([]byte, 512)
	for {
		// 读取UDP数据包
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println("Error reading:", err)
			continue
		}

		log.Printf("Received DNS query from %s\n", clientAddr.IP)

		// 解析DNS请求报文
		question, err := parseDNSQuestion(buffer[:n])
		if err != nil {
			log.Println("Error parsing DNS question:", err)
			continue
		}

		// 检查请求类型是否为A记录
		if question.Type == dnsTypeA {

			// 来自 {random-id}.domain 的请求
			if strings.HasSuffix(question.Name, "."+domain) {
				id, _ := strings.CutSuffix(question.Name, "."+domain)
				cache.SetCache(id, clientAddr.IP.String())
			}

			// 构建响应报文
			response := buildDNSResponse(question.Name, serverIPs[0].String())

			// 发送响应报文
			_, err := conn.WriteToUDP(response, clientAddr)
			if err != nil {
				log.Println("Error sending DNS response:", err)
				continue
			}

			log.Printf("Sent DNS response to %s\n", clientAddr.IP)
		}
	}
}

// 解析DNS请求报文中的问题部分
func parseDNSQuestion(data []byte) (*dnsQuestion, error) {
	var question dnsQuestion

	// 解析域名
	domainName, _, err := parseDomainName(data, 12)
	if err != nil {
		return nil, fmt.Errorf("failed to parse domain name: %w", err)
	}

	// 解析类型和类
	question.Name = domainName
	question.Type = uint16(data[len(data)-4])<<8 | uint16(data[len(data)-3])
	question.Class = uint16(data[len(data)-2])<<8 | uint16(data[len(data)-1])

	return &question, nil
}

// 构建DNS响应报文
func buildDNSResponse(name string, ip string) []byte {
	// 构建报文头部
	header := make([]byte, 12)
	header[1] = 0x81 // 设置标志位为响应报文
	header[3] = 0x01 // 设置问题数为1

	// 构建问题部分
	question, _ := buildDNSQuestion(name, dnsTypeA, dnsClassIN)

	// 构建回答部分
	answer, _ := buildDNSAnswer(name, dnsTypeA, dnsClassIN, 5, ip)

	// 拼接报文头部、问题部分和回答部分
	response := append(header, question...)
	response = append(response, answer...)

	return response
}

// 构建DNS问题部分
func buildDNSQuestion(name string, qType uint16, qClass uint16) ([]byte, error) {
	// 构建域名
	domainName, err := buildDomainName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to build domain name: %w", err)
	}

	// 构建类型和类
	qTypeBytes := []byte{byte(qType >> 8), byte(qType)}
	qClassBytes := []byte{byte(qClass >> 8), byte(qClass)}

	// 拼接域名、类型和类
	question := append(domainName, qTypeBytes...)
	question = append(question, qClassBytes...)

	return question, nil
}

// 构建DNS回答部分
func buildDNSAnswer(name string, aType uint16, aClass uint16, ttl uint32, ip string) ([]byte, error) {
	// 构建域名
	domainName, err := buildDomainName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to build domain name: %w", err)
	}

	// 构建类型和类
	aTypeBytes := []byte{byte(aType >> 8), byte(aType)}
	aClassBytes := []byte{byte(aClass >> 8), byte(aClass)}

	// 构建TTL
	ttlBytes := []byte{
		byte(ttl >> 24),
		byte(ttl >> 16),
		byte(ttl >> 8),
		byte(ttl),
	}

	// 构建数据```go
	ipBytes := net.ParseIP(ip).To4()

	// 构建数据长度
	dataLength := []byte{0x00, 0x04}

	// 拼接域名、类型、类、TTL、数据长度和数据
	answer := append(domainName, aTypeBytes...)
	answer = append(answer, aClassBytes...)
	answer = append(answer, ttlBytes...)
	answer = append(answer, dataLength...)
	answer = append(answer, ipBytes...)

	return answer, nil
}

// 构建域名
func buildDomainName(name string) ([]byte, error) {
	var domainName []byte

	labels := make([]string, 0)
	label := ""

	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			labels = append(labels, label)
			label = ""
		} else {
			label += string(name[i])
		}
	}

	labels = append(labels, label)

	for _, l := range labels {
		labelLength := byte(len(l))
		domainName = append(domainName, labelLength)
		domainName = append(domainName, []byte(l)...)
	}

	domainName = append(domainName, 0x00)

	return domainName, nil
}

// 解析域名
func parseDomainName(data []byte, offset int) (string, int, error) {
	var domainName string

	for {
		length := int(data[offset])
		offset++

		if length == 0 {
			break
		}

		if length >= 192 {
			pointer := int(data[offset]) + (length-192)*256
			offset++

			// 递归解析指针指向的域名
			pointerDomainName, _, err := parseDomainName(data, pointer)
			if err != nil {
				return "", offset, fmt.Errorf("failed to parse domain name: %w", err)
			}

			domainName += pointerDomainName
			break
		}

		label := string(data[offset : offset+length])
		domainName += label + "."
		offset += length
	}

	return domainName, offset, nil
}

// DNS请求报文中的问题部分
type dnsQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// DNS记录类型常量
const (
	dnsTypeA   = 1 // A记录
	dnsClassIN = 1 // IN类
)
