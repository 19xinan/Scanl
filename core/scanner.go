package core

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ScanPorts 扫描指定主机的指定端口，使用指定数量的并发线程
func ScanPorts(host string, ports []int, threads int) map[int]string {
	results := make(map[int]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	portChan := make(chan int, len(ports))

	// 启动指定数量的goroutines
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				service := scanPort(host, port)
				mu.Lock()
				results[port] = service
				mu.Unlock()
			}
		}()
	}

	// 将所有端口放入通道
	for _, port := range ports {
		portChan <- port
	}
	close(portChan)

	wg.Wait()
	return results
}

// scanPort 扫描单个端口
func scanPort(host string, port int) string {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 1*time.Second)
	if err != nil {
		return "Closed"
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {

		}
	}(conn)
	return identifyService(port)
}
