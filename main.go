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

	// 解析命令行参数：-h网段、-all全端口、-t线程数、-pwd指定密码文件、-output指定输出文件名（不指定默认输出）
	subnet := flag.String("h", "", "Target subnet for scanning (e.g., 192.168.10.0/24)")
	allPorts := flag.Bool("all", false, "Scan all ports (0-65535)")
	threads := flag.Int("t", 100, "Number of concurrent threads")
	passwordFile := flag.String("pwd", "pass.txt", "Password file for bruteforce")
	outputFile := flag.String("output", "scan_results.txt", "Output file for scan results")
	flag.Parse()
	//检查网段
	if *subnet == "" {
		fmt.Println("Usage: ScanL.exe -h <target_subnet> [-all] [-t N] [-pwd pass.txt] [-output scan_results.txt]")
		os.Exit(1)
	}

	// 打开输出文件
	outputFileHandle, err := os.OpenFile(*outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Printf("Error opening output file: %v\n", err)
		os.Exit(1)
	}
	defer outputFileHandle.Close()

	// 解析网段
	ips, err := expandCIDR(*subnet)
	if err != nil {
		fmt.Fprintf(outputFileHandle, "Error parsing subnet: %v\n", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	var mutex sync.Mutex
	var aliveHosts []string

	// 检测存活主机并输出到终端和文件
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			if isHostAlive(ip) {
				mutex.Lock()
				aliveHosts = append(aliveHosts, ip)
				mutex.Unlock()
				fmt.Printf("Host %s is alive\n", ip)
				fmt.Fprintf(outputFileHandle, "Host %s is alive\n", ip)
			} else {
				fmt.Printf("Host %s is not alive\n", ip)
				fmt.Fprintf(outputFileHandle, "Host %s is not alive\n", ip)
			}
		}(ip)
	}

	wg.Wait()

	// 输出存活主机到文件
	fmt.Fprintln(outputFileHandle, "Alive hosts in subnet:")
	for _, ip := range aliveHosts {
		fmt.Fprintln(outputFileHandle, ip)
	}

	var ports []int
	if *allPorts {
		ports = make([]int, 65536)
		for i := 0; i <= 65535; i++ {
			ports[i] = i
		}
	} else {
		ports = []int{21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 161, 194, 443, 445, 465, 587, 993, 995, 1433, 1521, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090, 7001, 9999, 6379, 9200, 9300, 27017} // 精简端口列表
	}

	// 扫描主机并输出结果到终端和文件
	for _, ip := range aliveHosts {
		fmt.Fprintf(outputFileHandle, "Scanning host: %s\n", ip)
		fmt.Printf("Scanning host: %s\n", ip)
		results := core.ScanPorts(ip, ports, *threads)

		fmt.Fprintf(outputFileHandle, "Open ports on host %s:\n", ip)
		fmt.Printf("Open ports on host %s:\n", ip)
		for port, service := range results {
			if service != "Closed" {
				fmt.Fprintf(outputFileHandle, "Port %d: %s\n", port, service)
				fmt.Printf("Port %d: %s\n", port, service)
			}
		}

		// 默认启用暴力破解模块，针对开启了SSH或RDP的端口
		if service, found := results[22]; found && service == "SSH" {
			fmt.Fprintln(outputFileHandle, "Starting bruteforce attack on SSH...")
			fmt.Println("Starting bruteforce attack on SSH...")
			bruteforce.Bruteforce(ip, 22, *passwordFile)
		}
		//RDP实现有问题暂存
		//if service, found := results[3389]; found && service == "RDP" {
		//	fmt.Fprintln(outputFileHandle, "Starting bruteforce attack on RDP...")
		//	fmt.Println("Starting bruteforce attack on RDP...")
		//	bruteforce.Bruteforce(ip, 3389, *passwordFile)
		//}

		fmt.Fprintln(outputFileHandle, "---------------------------------------------")
		fmt.Println("---------------------------------------------")
	}

	fmt.Printf("Scan results saved to %s\n", *outputFile)
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

// IP地址递增
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

	defer conn.Close()
	return true
}
