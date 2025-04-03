package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	Port            int
	State           bool
	Service         string
	Banner          string
	Version         string
	Vulnerabilities []Vulnerability
}

type Vulnerability struct {
	ID          string
	Description string
	Severity    string
	Reference   string
}

// commonPorts maps well-known ports to their service names
var commonPorts = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	443:   "HTTPS",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	6379:  "Redis",
	8080:  "HTTP-Proxy",
	27017: "MongoDB",
}

var vulnerabilityDB = []struct {
	Service       string
	Version       string
	Vulnerability Vulnerability
}{
	{
		Service: "SSH",
		Version: "OpenSSH_7.4",
		Vulnerability: Vulnerability{
			ID:          "CVE-2017-15906",
			Description: "The process_open function in sftp-server.c in OpenSSH before 7.6 does not properly prevent write operations in read-only mode",
			Severity:    "Medium",
			Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2017-15906",
		},
	},
	{
		Service: "HTTP",
		Version: "Apache/2.4.29",
		Vulnerability: Vulnerability{
			ID:          "CVE-2019-0211",
			Description: "Apache HTTP Server 2.4.17 to 2.4.38 - Local privilege escalation through mod_prefork and mod_http2",
			Severity:    "High",
			Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2019-0211",
		},
	},
	{
		Service: "HTTP",
		Version: "Apache/2.4.41",
		Vulnerability: Vulnerability{
			ID:          "CVE-2020-9490",
			Description: "A specially crafted value for the 'Cache-Digest' header can cause a heap overflow in Apache HTTP Server 2.4.0-2.4.41",
			Severity:    "High",
			Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2020-9490",
		},
	},
	{
		Service: "MySQL",
		Version: "5.7",
		Vulnerability: Vulnerability{
			ID:          "CVE-2020-2922",
			Description: "Vulnerability in MySQL Server allows unauthorized users to obtain sensitive information",
			Severity:    "Medium",
			Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2020-2922",
		},
	},
	// Add more known vulnerabilities here
}

func main() {
	hostPtr := flag.String("host", "", "Target host to scan (required)")
	startPortPtr := flag.Int("start", 1, "Starting port number")
	endPortPtr := flag.Int("end", 1024, "Ending port number")
	timeoutPtr := flag.Int("timeout", 1000, "Timeout in milliseconds")
	concurrencyPtr := flag.Int("concurrency", 100, "Number of concurrent scans")
	formatPtr := flag.String("format", "text", "Output format: text, json, or csv")
	verbosePtr := flag.Bool("verbose", false, "Show verbose output including banners")
	outputFilePtr := flag.String("output", "", "Output file (default is stdout)")

	flag.Parse()

	if *hostPtr == "" {
		fmt.Println("Error: host is required")
		flag.Usage()
		os.Exit(1)
	}

	if *startPortPtr < 1 || *startPortPtr > 65535 {
		fmt.Println("Error: starting port must be between 1 and 65535")
		os.Exit(1)
	}
	if *endPortPtr < 1 || *endPortPtr > 65535 {
		fmt.Println("Error: ending port must be between 1 and 65535")
		os.Exit(1)
	}
	if *startPortPtr > *endPortPtr {
		fmt.Println("Error: starting port must be less than or equal to ending port")
		os.Exit(1)
	}

	timeout := time.Duration(*timeoutPtr) * time.Millisecond

	var outputFile *os.File
	var err error

	if *outputFilePtr != "" {
		outputFile, err = os.Create(*outputFilePtr)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer outputFile.Close()
	} else {
		outputFile = os.Stdout
	}

	fmt.Fprintf(outputFile, "Scanning %s from port %d to %d\n", *hostPtr, *startPortPtr, *endPortPtr)
	startTime := time.Now()

	var results []ScanResult
	var wg sync.WaitGroup

	resultChan := make(chan ScanResult, *endPortPtr-*startPortPtr+1)

	semaphore := make(chan struct{}, *concurrencyPtr)

	for port := *startPortPtr; port <= *endPortPtr; port++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := scanPort(*hostPtr, p, timeout)
			resultChan <- result
		}(port)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		if result.State {
			results = append(results, result)
		}
	}

	elapsed := time.Since(startTime)

	switch *formatPtr {
	case "json":
		outputJSON(outputFile, results, elapsed)
	case "csv":
		outputCSV(outputFile, results, elapsed, *verbosePtr)
	default:
		outputText(outputFile, results, elapsed, *verbosePtr)
	}
}

func scanPort(host string, port int, timeout time.Duration) ScanResult {
	target := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return ScanResult{Port: port, State: false}
	}
	conn.Close()

	banner, err := grabBanner(host, port, timeout)
	if err != nil {
		return ScanResult{Port: port, State: false}
	}
	service := "Unknown"
	version := "Unknown"
	if banner != "" {
		service, version = identifyService(port, banner)
	}
	vulnerabilities := checkVulnerabilities(service, version)

	return ScanResult{
		Port:            port,
		State:           true,
		Service:         service,
		Version:         version,
		Banner:          banner,
		Vulnerabilities: vulnerabilities,
	}
}

// checkVulnerabilities checks if a service/version combination has known vulnerabilities
func checkVulnerabilities(service, version string) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, vuln := range vulnerabilityDB {
		// Simple matching - in a real scanner, this would be more sophisticated
		if vuln.Service == service && strings.Contains(version, vuln.Version) {
			vulnerabilities = append(vulnerabilities, vuln.Vulnerability)
		}
	}

	return vulnerabilities
}

// grabBanner attempts to read the banner from an open port
func grabBanner(host string, port int, timeout time.Duration) (string, error) {
	target := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))
	if port == 80 || port == 443 || port == 8080 || port == 8443 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	} else {

	}

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(banner), nil
}

func identifyService(port int, banner string) (service, version string) {
	service = getServiceNameFromPort(port)
	if banner == "" {
		return service, "Unknown"
	}

	lowerBanner := strings.ToLower(banner)
	// Try to identify specific services
	switch {
	case strings.Contains(lowerBanner, "ssh"):
		parts := strings.Split(banner, " ")
		version := "Unknown"
		if len(parts) >= 2 {
			version = parts[1]
		}
		return "SSH", version
	case isHTTPService(lowerBanner):
		service = "HTTP"
		if port == 443 {
			service = "HTTPS"
		}

		if strings.Contains(banner, "Server:") {
			parts := strings.Split(banner, "Server:")
			if len(parts) >= 2 {
				version = strings.TrimSpace(parts[1])
			}
		}
	}

	return service, version
}

func getServiceNameFromPort(port int) string {
	if service, exists := commonPorts[port]; exists {
		return service
	}
	return "Unknown"
}

func isHTTPService(lowerBanner string) bool {
	return strings.Contains(lowerBanner, "http") ||
		strings.Contains(lowerBanner, "apache") ||
		strings.Contains(lowerBanner, "nginx")
}

func outputText(w *os.File, results []ScanResult, elapsed time.Duration, verbose bool) {
	fmt.Fprintf(w, "\nScan completed in %s\n", elapsed)
	fmt.Fprintf(w, "Found %d open ports:\n\n", len(results))

	if len(results) == 0 {
		fmt.Fprintf(w, "No open ports found.\n")
		return
	}

	fmt.Fprintf(w, "PORT\tSERVICE\tVERSION\n")
	fmt.Fprintf(w, "----\t-------\t-------\n")

	for _, result := range results {
		fmt.Fprintf(w, "%d\t%s\t%s\n",
			result.Port,
			result.Service,
			result.Version)

		if verbose {
			fmt.Fprintf(w, "  Banner: %s\n", result.Banner)
		}

		if len(result.Vulnerabilities) > 0 {
			fmt.Fprintf(w, "  Vulnerabilities:\n")
			for _, vuln := range result.Vulnerabilities {
				fmt.Fprintf(w, "    [%s] %s - %s\n",
					vuln.Severity,
					vuln.ID,
					vuln.Description)
				fmt.Fprintf(w, "    Reference: %s\n\n", vuln.Reference)
			}
		}
	}
}

func outputJSON(w *os.File, results []ScanResult, elapsed time.Duration) {
	output := struct {
		ScanTime    string       `json:"scan_time"`
		ElapsedTime string       `json:"elapsed_time"`
		TotalPorts  int          `json:"total_ports"`
		OpenPorts   int          `json:"open_ports"`
		Results     []ScanResult `json:"results"`
	}{
		ScanTime:    time.Now().Format(time.RFC3339),
		ElapsedTime: elapsed.String(),
		TotalPorts:  0,
		OpenPorts:   len(results),
		Results:     results,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(output)
}

func outputCSV(w *os.File, results []ScanResult, elapsed time.Duration, verbose bool) {
	fmt.Fprintf(w, "Port,Service,Version,Vulnerability ID,Severity,Description\n")

	for _, result := range results {
		if len(result.Vulnerabilities) == 0 {
			fmt.Fprintf(w, "%d,%s,%s,,,\n",
				result.Port,
				escapeCSV(result.Service),
				escapeCSV(result.Version))
		} else {
			for _, vuln := range result.Vulnerabilities {
				fmt.Fprintf(w, "%d,%s,%s,%s,%s,%s\n",
					result.Port,
					escapeCSV(result.Service),
					escapeCSV(result.Version),
					escapeCSV(vuln.ID),
					escapeCSV(vuln.Severity),
					escapeCSV(vuln.Description))
			}
		}
	}

	fmt.Fprintf(w, "\n# Scan completed in %s, found %d open ports\n",
		elapsed, len(results))
}

func escapeCSV(s string) string {
	if strings.Contains(s, ",") || strings.Contains(s, "\"") || strings.Contains(s, "\n") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}
