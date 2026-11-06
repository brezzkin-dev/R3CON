package t40_portx

import (
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

type Options struct {
	Target  string
	Ports   string
	Timeout time.Duration
	Workers int
}

type openPort struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
	TLS     bool   `json:"tls,omitempty"`
}

var topPorts = []int{
	21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
	143, 161, 162, 179, 389, 443, 445, 465, 500, 512, 513, 514, 515, 520,
	548, 554, 587, 623, 631, 636, 873, 902, 989, 990, 993, 995, 1080, 1194,
	1433, 1434, 1521, 1701, 1723, 1755, 1812, 1813, 2000, 2049, 2082, 2083,
	2086, 2087, 2095, 2096, 2222, 2375, 2376, 2483, 2484, 3000, 3128, 3260,
	3306, 3389, 3690, 4000, 4369, 4444, 5000, 5060, 5061, 5222, 5353, 5432,
	5555, 5601, 5672, 5683, 5900, 5984, 6000, 6379, 6667, 7001, 7002, 8000,
	8008, 8080, 8081, 8086, 8088, 8090, 8125, 8443, 8888, 9000, 9090, 9092,
	9100, 9200, 9300, 9418, 9443, 9999, 10000, 11211, 15672, 16379, 25565,
	27017, 27018, 28017, 50000, 50070, 50075, 61616,
}

var serviceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 139: "netbios",
	143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
	465: "smtps", 587: "submission", 636: "ldaps", 993: "imaps",
	995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle",
	2049: "nfs", 2375: "docker", 2376: "docker-tls", 3306: "mysql",
	3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
	8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
	11211: "memcached", 27017: "mongodb",
}

func Run(opts Options) (*core.Result, error) {
	r := core.NewResult("portx", opts.Target)

	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.Workers <= 0 {
		opts.Workers = 500
	}

	hosts, err := expandTargets(opts.Target)
	if err != nil {
		return r, err
	}
	if len(hosts) > 4096 {
		return r, fmt.Errorf("target expands to %d hosts (>4096) — narrow the CIDR", len(hosts))
	}

	ports, err := parsePorts(opts.Ports)
	if err != nil {
		return r, err
	}

	r.AddExtra("host_count", len(hosts))
	r.AddExtra("port_count", len(ports))

	type task struct {
		host string
		port int
	}
	tasks := make(chan task, opts.Workers*2)
	var results []openPort
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				if op := probePort(t.host, t.port, opts.Timeout); op != nil {
					mu.Lock()
					results = append(results, *op)
					mu.Unlock()
				}
			}
		}()
	}

	for _, h := range hosts {
		for _, p := range ports {
			tasks <- task{h, p}
		}
	}
	close(tasks)
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].Host != results[j].Host {
			return results[i].Host < results[j].Host
		}
		return results[i].Port < results[j].Port
	})

	r.AddExtra("open_ports", results)
	r.AddExtra("open_count", len(results))

	for _, op := range results {
		sev := core.SevLow
		if isDangerous(op.Port) {
			sev = core.SevHigh
		} else if isInteresting(op.Port) {
			sev = core.SevMed
		}
		r.Add(core.Finding{
			Tool: "portx", Severity: sev,
			Title:  fmt.Sprintf("%s:%d %s", op.Host, op.Port, op.Service),
			Detail: op.Banner,
		})
	}
	r.Finish()
	return r, nil
}

func probePort(host string, port int, timeout time.Duration) *openPort {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	op := &openPort{
		Host: host, Port: port,
		Service: serviceNames[port],
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)

	switch port {
	case 80, 8080, 8000:
		conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + host + "\r\n\r\n"))
	case 21, 22, 25, 110, 143, 587:
	default:
		conn.Write([]byte("\r\n"))
	}

	n, _ := conn.Read(buf)
	if n > 0 {
		op.Banner = strings.TrimSpace(string(buf[:n]))
		if len(op.Banner) > 200 {
			op.Banner = op.Banner[:200]
		}
	}

	if port == 443 || port == 8443 || port == 465 || port == 636 || port == 993 || port == 995 {
		cfg := &tls.Config{InsecureSkipVerify: true, ServerName: host}
		tc, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, cfg)
		if err == nil {
			op.TLS = true
			tc.Close()
		}
	}

	return op
}

func expandTargets(target string) ([]string, error) {
	if strings.Contains(target, "/") {
		_, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			return nil, err
		}
		var out []string
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			out = append(out, ip.String())
		}
		if len(out) > 2 {
			out = out[1 : len(out)-1]
		}
		return out, nil
	}
	if net.ParseIP(target) == nil {
		ips, err := net.LookupHost(target)
		if err != nil {
			return nil, err
		}
		return ips, nil
	}
	return []string{target}, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parsePorts(spec string) ([]int, error) {
	switch spec {
	case "top", "":
		return topPorts, nil
	case "full":
		out := make([]int, 65535)
		for i := 0; i < 65535; i++ {
			out[i] = i + 1
		}
		return out, nil
	}
	if strings.Contains(spec, "-") && !strings.Contains(spec, ",") {
		parts := strings.SplitN(spec, "-", 2)
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
			return nil, fmt.Errorf("invalid port range %q", spec)
		}
		out := make([]int, 0, hi-lo+1)
		for p := lo; p <= hi; p++ {
			out = append(out, p)
		}
		return out, nil
	}
	var out []int
	for _, p := range strings.Split(spec, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		out = append(out, n)
	}
	return out, nil
}

func isDangerous(port int) bool {
	switch port {
	case 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 2375, 27017:
		return true
	}
	return false
}

func isInteresting(port int) bool {
	switch port {
	case 21, 22, 25, 53, 139, 111, 389, 636:
		return true
	}
	return false
}
