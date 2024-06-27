package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"scanl/bruteforce"
	"scanl/core"
)

func main() {
	fmt.Println(`
  ██████  ▄████▄   ▄▄▄       ███▄    █  ██▓    
▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █ ▓██▒    
░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒▒██░    
  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒▒██░    
▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░░██████▒
▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ▒░▓  ░
░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░░ ░ ▒  ░
░  ░  ░  ░          ░   ▒      ░   ░ ░   ░ ░   
      ░  ░ ░            ░  ░         ░     ░  ░
         ░
	`)
	// 解析命令行参数
	subnet := flag.String("h", "", "Target subnet for scanning (e.g., 192.168.10.0/24)")
	allPorts := flag.Bool("all", false, "Scan all ports (0-65535)")
	threads := flag.Int("t", 100, "Number of concurrent threads")
	passwordFile := flag.String("pwd", "pass.txt", "Password file for bruteforce")
	flag.Parse()

	if *subnet == "" {
		fmt.Println("Usage: go run main.go -subnet <target_subnet> [-all] [-threads N] [-passfile pass.txt]")
		os.Exit(1)
	}

	ips, err := expandCIDR(*subnet)
	if err != nil {
		fmt.Printf("Error parsing subnet: %v\n", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	var mutex sync.Mutex
	var aliveHosts []string

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			if isHostAlive(ip) {
				mutex.Lock()
				aliveHosts = append(aliveHosts, ip)
				mutex.Unlock()
			}
		}(ip)
	}

	wg.Wait()

	fmt.Println("Alive hosts in subnet:")
	for _, ip := range aliveHosts {
		fmt.Println(ip)
	}

	var ports []int
	if *allPorts {
		ports = make([]int, 65536)
		for i := 0; i <= 65535; i++ {
			ports[i] = i
		}
	} else {
		ports = []int{21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 161, 194, 443, 445, 465, 587, 993, 995, 1433, 1521, 1723, 3306, 3389, 5900, 8080} // 精简端口列表
	}

	for _, ip := range aliveHosts {
		fmt.Printf("Scanning host: %s\n", ip)
		results := core.ScanPorts(ip, ports, *threads)

		fmt.Printf("Open ports on host %s:\n", ip)
		for port, service := range results {
			if service != "Closed" {
				fmt.Printf("Port %d: %s\n", port, service)
			}
		}

		// 默认启用暴力破解模块，针对开启了SSH或RDP的端口
		if service, found := results[22]; found && service == "SSH" {
			fmt.Println("Starting bruteforce attack on SSH...")
			bruteforce.Bruteforce(ip, 22, *passwordFile)
		}
		if service, found := results[3389]; found && service == "RDP" {
			fmt.Println("Starting bruteforce attack on RDP...")
			bruteforce.Bruteforce(ip, 3389, *passwordFile)
		}

		fmt.Println("---------------------------------------------")
	}
}

// expandCIDR 解析网段，生成所有 IP 地址
func expandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// 排除网络地址和广播地址
	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		break
	case lenIPs > 2:
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// isHostAlive 检测主机是否存活
func isHostAlive(ip string) bool {
	timeout := 2 * time.Second
	conn, err := net.DialTimeout("ip4:icmp", ip, timeout)
	if err != nil {
		return false
	}

	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {

		}
	}(conn)
	return true
}
