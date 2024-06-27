package core

// identifyService 根据端口号识别服务
func identifyService(port int) string {
	services := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		119:   "NNTP",
		123:   "NTP",
		143:   "IMAP",
		161:   "SNMP",
		194:   "IRC",
		443:   "HTTPS",
		445:   "SMB",
		465:   "SMTPS",
		587:   "Submission",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "MSSQL",
		1521:  "Oracle DB",
		1723:  "PPTP",
		3306:  "MySQL",
		3389:  "RDP",
		5900:  "VNC",
		8080:  "HTTP-Proxy",
		8443:  "HTTPS-Alt",
		8888:  "HTTP-Alt",
		9090:  "Weblogic",
		7001:  "Weblogic-Alt",
		9999:  "HTTP-Alt2",
		6379:  "Redis",
		9200:  "Elasticsearch",
		9300:  "Elasticsearch-Transport",
		27017: "MongoDB",
	}

	if service, found := services[port]; found {
		return service
	}
	return "Unknown"
}
