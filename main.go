package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"
)

// This document is Licensed under Creative Commons CC0.
// To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights
// to this document to the public domain worldwide.
// This document is distributed without any warranty.
// You should have received a copy of the CC0 Public Domain Dedication along with this document.
// If not, see https://creativecommons.org/publicdomain/zero/1.0/legalcode.

// EPER Jetstream Database is a low complexity data and code storage solution. It is a hardened file system that you can review, verify, and certify cheaper.
// We do not allow it to grow more than 1000 lines of code. This allows users to customize with AI tools.
// No branding. It just works mostly for distributed in memory storage like Redis, Memcached or SAP Hana.

var root = "/data"
var retention = 10 * time.Minute
var marker = "dat"
var fileExtension = fmt.Sprintf(".%s", marker)
var sslLocation = fmt.Sprintf("%s", marker)

const MaxFileSize = 128 * 1024 * 1024
const MaxMemSize = 4 * MaxFileSize

// Cluster endpoint
var cluster = "http://127.0.0.1:7777"

// Snapshot topology
var nodes = [][]string{{"http://127.0.0.1:7777"}, {"https://18.209.57.108:443"}}

// Reliability measures
var pinnedIP = map[string]string{"127.0.0.1": "localhost", "18.209.57.108": "hour.schmied.us"}
var rateLimitIng sync.Mutex

// Fairly unique instance ID to avoid routing loops. TODO uuidgen?
var instance = fmt.Sprintf("%d", time.Now().UnixNano()+rand.Int63())

const routedCall = "09E3F5F0-1D87-4B54-B57D-8D046D001942"
const depthCall = "9D2D182E-0F2D-42D8-911B-071443F8D21C"

// Pools avoid deadlocks and bottlenecks due to memory allocation.
var level1Pool = make(chan []byte, MaxMemSize/MaxFileSize)
var level2Pool = make(chan []byte, MaxMemSize/MaxFileSize)

// The startup time is used to determine if the system is still warming up.
var startupTime = time.Now()

const AppendOnlySecret = "Append only channel to segment "
const WriteOnlySecret = "Write only channel to segment "
const ReadOnlySecret = "Read only channel to segment "

var client = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func NewRequestWithPinnedIP(urlStr, method string, body []byte) (*http.Request, *http.Client, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, nil, err
	}
	ip := u.Hostname()
	host, ok := pinnedIP[ip]
	if !ok {
		return nil, nil, fmt.Errorf("no pinned host for IP: %s", ip)
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	ipPort := ip + ":" + port
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: host},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, ipPort)
		},
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	// Set Host header for SNI
	req.Host = host
	return req, client, nil
}

func main() {
	_, err := os.Stat(root)
	if err != nil {
		fallback := "/tmp"
		root = fallback
	}
	Setup()
	keyPath := fmt.Sprintf("/etc/ssl/%s.key", sslLocation)
	crtPath := fmt.Sprintf("/etc/ssl/%s.crt", sslLocation)
	_, err = os.Stat(keyPath)
	if err == nil {
		err = http.ListenAndServeTLS(":443", crtPath, keyPath, nil)
	} else {
		_ = http.ListenAndServe(":7777", nil)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func Setup() {
	for i := 0; i < MaxMemSize/MaxFileSize; i++ {
		level1Pool <- make([]byte, MaxFileSize)
	}
	// Allocate level2Pool only if any node group has more than one member (enables distributed routing)
	needLevel2 := false
	for _, grp := range nodes {
		if len(grp) > 1 {
			needLevel2 = true
			break
		}
	}
	if needLevel2 {
		for i := 0; i < MaxMemSize/MaxFileSize; i++ {
			level2Pool <- make([]byte, MaxFileSize)
		}
	}
	go func() {
		for {
			now := time.Now()
			list, _ := os.ReadDir(root)
			for _, v := range list {
				if IsValidDatHash("/" + v.Name()) {
					filePath := path.Join(root, v.Name())
					stat, _ := os.Stat(filePath)
					if stat != nil {
						if stat.ModTime().Add(retention).Before(now) {
							_ = os.Remove(filePath)
						}
					}
				}
				time.Sleep(retention / time.Duration(len(list)) / 10)
			}
			time.Sleep(retention)
		}
	}()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") || strings.Contains(r.URL.Path, "./") {
			// This is stricter than path.Clear reducing complexity.
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		runtime.GC()
		client.CloseIdleConnections()
		depth := GetDepth(r)
		// Use nodes fan-out when more than one node in the selected depth group instead of cluster check
		if len(nodes) > 0 && depth < len(nodes) && len(nodes[depth]) > 1 && !IsCallRouted(w, r) {
			fulfillRequestByCluster(w, r)
			return
		}
		buffer := <-level1Pool
		defer func(a0 []byte) {
			for i := range a0 {
				a0[i] = 0
			}
			level1Pool <- a0
		}(buffer)
		var body []byte
		if r.Body != nil {
			buf := bytes.NewBuffer(buffer)
			buf.Reset()
			n, _ := io.Copy(buf, io.LimitReader(r.Body, MaxFileSize))
			body = buf.Bytes()[0:n]
			_ = r.Body.Close()
		}

		fulfillRequestLocally(w, r, body)
	})
}

func fulfillRequestLocally(w http.ResponseWriter, r *http.Request, body []byte) {
	if r.Method == "PUT" || r.Method == "POST" {
		if r.URL.Path == "/kv" {
			// We allow key value pairs for limited use of persistent checkpoints, commits, and tags
			shortName := fmt.Sprintf("%x%s", sha256.Sum256(body), fileExtension)
			_, _ = io.WriteString(w, "/"+shortName)
			return
		}
		if QuantumGradeAuthenticationFailed(w, r) {
			return
		}
		w.WriteHeader(http.StatusOK)
		if IsValidDatHash(r.URL.Path) {
			WriteVolatile(w, r, body)
		} else {
			WriteNonVolatile(w, r, body)
		}
		depth := GetDepth(r)
		if next := depth + 1; next < len(nodes) && len(nodes[next]) > 0 {
			bc := nodes[next][rand.Intn(len(nodes[next]))]
			BackupToChain(bc, r, body)
		}
		return
	}
	if r.Method == "DELETE" {
		if !IsValidDatHash(r.URL.Path) {
			w.WriteHeader(http.StatusExpectationFailed)
			return
		}
		if QuantumGradeAuthenticationFailed(w, r) {
			return
		}
		if DeleteVolatile(w, r) {
			_, _ = io.WriteString(w, r.URL.Path)
		}
		depth := GetDepth(r)
		if next := depth + 1; next < len(nodes) && len(nodes[next]) > 0 {
			bc := nodes[next][rand.Intn(len(nodes[next]))]
			DeleteToChain(bc, r)
		}
		return
	}

	// Dynamic restore: depth n uses random node from nodes[n+1] if exists during warmup window
	depth := GetDepth(r)
	next := depth + 1
	if next < len(nodes) && len(nodes[next]) > 0 && time.Now().Before(startupTime.Add(retention)) && !IsCallRouted(w, r) {
		if (r.Method == "HEAD" || r.Method == "GET") && IsValidDatHash(r.URL.Path) {
			_, err := os.Stat(path.Join(root, r.URL.Path))
			if err != nil {
				rc := nodes[next][rand.Intn(len(nodes[next]))]
				RestoreFromChain(rc, w, r)
			}
		}
	}

	if r.Method == "HEAD" {
		if !IsValidDatHash(r.URL.Path) {
			w.WriteHeader(http.StatusExpectationFailed)
			return
		}
		_, err := os.Stat(path.Join(root, r.URL.Path))
		if err != nil {
			QuantumGradeError()
			w.WriteHeader(http.StatusNotFound)
			return
		}
		QuantumGradeSuccess()
		w.WriteHeader(http.StatusOK)
		return
	}
	take := r.Method == "GET" && r.URL.Query().Get("take") == "1"
	if r.Method == "GET" {
		if r.URL.Path == "/" {
			if QuantumGradeAuthenticationFailed(w, r) {
				return
			}
			// Reserved for use by wrappers or backup triggers
			return
		} else {
			ReadStore(w, r)
			if take {
				DeleteVolatile(w, r)
			}
		}
	}
}

func fulfillRequestByCluster(w http.ResponseWriter, r *http.Request) {
	buffer := <-level2Pool
	defer func(a0 []byte) {
		for i := range a0 {
			a0[i] = 0
		}
		level2Pool <- a0
	}(buffer)
	var body []byte
	if r.Body != nil {
		buf := bytes.NewBuffer(buffer)
		buf.Reset()
		n, _ := io.Copy(buf, io.LimitReader(r.Body, MaxFileSize))
		body = buf.Bytes()[0:n]
		_ = r.Body.Close()
	}
	bodyHash := fmt.Sprintf("%x%s", sha256.Sum256(body), fileExtension)

	remoteAddress := ""
	depth := GetDepth(r)
	var list []string
	if depth >= 0 && depth < len(nodes) {
		list = nodes[depth]
	}
	for _, clusterAddress := range list {
		// Normalize clusterAddress to host (strip scheme if present)
		verifyAddress, _, forwardAddress := DistributedAddress(r, bodyHash, clusterAddress)
		if DistributedCheck(verifyAddress) {
			remoteAddress = forwardAddress
		}
	}
	if remoteAddress != "" {
		DistributedCall(w, r, r.Method, body, remoteAddress)
		return
	}
	fulfillRequestLocally(w, r, body)
	return
}

func ReadStore(w http.ResponseWriter, r *http.Request) {
	mimeType := r.URL.Query().Get("Content-Type")
	if mimeType != "" {
		w.Header().Set("Content-Type", mimeType)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	status := ReadStoreBuffer(w, r)
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
}

func ReadStoreBuffer(w io.Writer, r *http.Request) int {
	if !IsValidDatHash(r.URL.Path) {
		return http.StatusExpectationFailed
	}
	// Hashes are strong enough not to require an apikey TODO os.Link()
	filePath := path.Join(root, r.URL.Path)
	data, err := os.ReadFile(filePath)
	if err != nil {
		QuantumGradeError()
		return http.StatusNotFound
	}

	if len(data) < 120 {
		if strings.HasPrefix(string(data), WriteOnlySecret) || strings.HasPrefix(string(data), AppendOnlySecret) {
			return http.StatusForbidden
		}
		if strings.HasPrefix(string(data), ReadOnlySecret) {
			secretHash := string(data)[len(ReadOnlySecret):]
			if IsValidDatHash(secretHash) && cluster != "" {
				response, err := http.Get(cluster + secretHash)
				if err == nil {
					_, err = io.Copy(w, response.Body)
					err = response.Body.Close()
					return http.StatusOK
				}
			}
			return http.StatusForbidden
		}
	}
	if r.URL.Query().Get("burst") == "1" {
		scanner := bufio.NewScanner(bytes.NewBuffer(data))
		for scanner.Scan() {
			line := scanner.Text()
			if IsValidDatHash(line) && cluster != "" {
				req, client, err := NewRequestWithPinnedIP(cluster+line, "GET", nil)
				if err == nil {
					resp, err := client.Do(req)
					if err == nil && resp.StatusCode == http.StatusOK {
						_, _ = io.Copy(w, resp.Body)
					}
					if resp != nil && resp.Body != nil {
						_ = resp.Body.Close()
					}
				}
			}
		}
	} else {
		NoIssueWrite(w.Write(data))
		MarkAsUsed(r, filePath)
	}
	return http.StatusOK
}

func MarkAsUsed(r *http.Request, fileName string) {
	chTimes := "1"
	param := r.URL.Query().Get("chtimes")
	if param != "" {
		chTimes = param
	}
	if chTimes != "0" {
		current := time.Now()
		_ = os.Chtimes(fileName, current, current)
	}
}

func DeleteVolatile(w http.ResponseWriter, r *http.Request) bool {
	if !IsValidDatHash(r.URL.Path) {
		return false
	}
	if len(r.URL.Path) <= 1 {
		return false
	}

	// We allow deletion of key value pairs but not non-volatile hashed storage
	shortName := r.URL.Path[1:]
	absolutePath := path.Join(root, shortName)

	data, _ := os.ReadFile(absolutePath)
	shortNameOnDisk := fmt.Sprintf("%x%s", sha256.Sum256(data), fileExtension)
	if shortNameOnDisk == shortName {
		// Disallow updating secure hashed segments already stored.
		QuantumGradeError()
		return false
	}
	if len(data) < 120 {
		if strings.HasPrefix(string(data), ReadOnlySecret) {
			QuantumGradeError()
			return false
		}
		if strings.HasPrefix(string(data), WriteOnlySecret) {
			QuantumGradeError()
			return false
		}
		if strings.HasPrefix(string(data), AppendOnlySecret) {
			QuantumGradeError()
			return false
		}
	}
	filePath := path.Join(root, r.URL.Path)
	if os.Remove(filePath) != nil {
		return false
	}
	return true
}

func WriteVolatile(w http.ResponseWriter, r *http.Request, body []byte) {
	if !IsValidDatHash(r.URL.Path) {
		return
	}
	if len(r.URL.Path) <= 1 {
		return
	}
	// We allow key value pairs for limited use of checkpoints, commits, and persistence tags
	shortName := r.URL.Path[1:]
	absolutePath := path.Join(root, shortName)

	data, _ := os.ReadFile(absolutePath)
	shortNameOnDisk := fmt.Sprintf("%x%s", sha256.Sum256(data), fileExtension)
	if shortNameOnDisk == shortName {
		// Disallow updating secure hashed segments already stored.
		QuantumGradeError()
		return
	}
	if len(data) < 120 {
		if strings.HasPrefix(string(data), ReadOnlySecret) {
			return
		}
		if strings.HasPrefix(string(data), WriteOnlySecret) {
			secretHash := string(data)[len(WriteOnlySecret):]
			if IsValidDatHash(secretHash) && cluster != "" {
				var query = r.URL.Query().Encode()
				if len(query) > 0 {
					query = "?" + query
				}
				response, err := http.Post(cluster+secretHash+query, "text/plain", bytes.NewBuffer(body))
				if err == nil {
					io.WriteString(w, r.URL.Path)
					err = response.Body.Close()
					return
				}
			}
			return
		}
		if strings.HasPrefix(string(data), AppendOnlySecret) {
			secretHash := string(data)[len(AppendOnlySecret):]
			if IsValidDatHash(secretHash) && cluster != "" {
				if r.URL.Query().Get("append") != "1" {
					return
				}
				var query = r.URL.Query().Encode()
				if len(query) > 0 {
					query = "?" + query
				}
				response, err := http.Post(cluster+secretHash+query, "text/plain", bytes.NewBuffer(body))
				if err == nil {
					io.WriteString(w, r.URL.Path)
					err = response.Body.Close()
					return
				}
			}
			return
		}
	}
	setIfNot := r.URL.Query().Get("setifnot") == "1"
	flags := os.O_CREATE | os.O_WRONLY
	if setIfNot {
		// Key value pairs may collide. We do not use file system locks to allow pure in memory storage later
		flags = flags | os.O_EXCL
	}
	appendIndex := r.URL.Query().Get("append") == "1"
	if appendIndex {
		flags = flags | os.O_APPEND
	} else {
		flags = flags | os.O_TRUNC
	}
	file, err := os.OpenFile(absolutePath, flags, 0600)
	if err == nil {
		_, _ = io.Copy(file, bytes.NewBuffer(body))
		_ = file.Close()
	} else {
		if setIfNot {
			return
		}
	}
	formatted := FormattedReturnValue(r, shortName)
	_, _ = io.WriteString(w, formatted)
}

func WriteNonVolatile(w http.ResponseWriter, r *http.Request, body []byte) {
	if len(r.URL.Path) > 1 || r.URL.Path != "/" {
		return
	}
	shortName := fmt.Sprintf("%x%s", sha256.Sum256(body), fileExtension)
	absolutePath := path.Join(root, shortName)
	flags := os.O_CREATE | os.O_TRUNC | os.O_WRONLY | os.O_EXCL
	file, err := os.OpenFile(absolutePath, flags, 0600)
	if err == nil {
		_, _ = io.Copy(file, bytes.NewBuffer(body))
		_ = file.Close()
	}
	formatted := FormattedReturnValue(r, shortName)
	_, _ = io.WriteString(w, formatted)
}

func FormattedReturnValue(r *http.Request, shortName string) string {
	format := Nvl(r.URL.Query().Get("format"), "*")
	// TODO Audit the use of external format with Sprintf
	relativePath := path.Join("/", shortName)
	formatted := fmt.Sprintf(strings.Replace(format, "*", "%s", 1), relativePath)
	return formatted
}

func IsCallRouted(w http.ResponseWriter, r *http.Request) bool {
	u, _ := url.Parse(r.URL.String())
	return u.Query().Get(routedCall) != ""
}

func DistributedAddress(r *http.Request, bodyHash, clusterAddress string) (string, string, string) {
	u := url.URL{Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	parsed, err := url.Parse(clusterAddress)
	if err == nil {
		u.Scheme = parsed.Scheme
		u.Host = parsed.Host
	} else {
		u.Scheme = "http"
		u.Host = clusterAddress + ":7777"
	}
	q := u.Query()
	q.Add(routedCall, instance)
	u.RawQuery = q.Encode()
	forwardAddress := u.String()
	if (strings.ToUpper(r.Method) == "PUT" || strings.ToUpper(r.Method) == "POST") && (r.URL.Path == "" || r.URL.Path == "/") {
		u.Path = "/" + bodyHash
	}
	verifyAddress := u.String()
	u.Path = "/"
	rootAddress := u.String()
	return verifyAddress, rootAddress, forwardAddress
}

func DistributedCheck(address string) bool {
	req, client, err := NewRequestWithPinnedIP(address, "HEAD", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil || resp == nil {
		return false
	}
	if resp.StatusCode != http.StatusOK {
		return false
	}
	return true
}

func DistributedCall(w http.ResponseWriter, r *http.Request, method string, body []byte, address string) bool {
	req, client, err := NewRequestWithPinnedIP(address, method, body)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil || resp == nil || resp.Body == nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return false
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	_ = resp.Body.Close()
	return true
}

func IsValidDatHash(path string) bool {
	// We do not want to return anything else but hashed files
	return strings.HasSuffix(path, fileExtension) && len(path) == len(fmt.Sprintf("/%x%s", sha256.Sum256([]byte("")), fileExtension))
}

func QuantumGradeAuthenticationFailed(w http.ResponseWriter, r *http.Request) bool {
	referenceApiKey := os.Getenv("APIKEY")
	if referenceApiKey == "" {
		// TODO This can use a kv pair
		apiKeyContent, _ := os.ReadFile(path.Join(root, "apikey"))
		if apiKeyContent != nil && len(apiKeyContent) > 0 {
			referenceApiKey = strings.Trim(string(apiKeyContent), "\r\n")
		}
	}
	apiKey := r.URL.Query().Get("apikey")
	if referenceApiKey != apiKey {
		QuantumGradeError()
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}
	// Let legitimate users use the system in parallel.
	QuantumGradeSuccess()
	return false
}

func QuantumGradeSuccess() {
	time.Sleep(2 * time.Millisecond)
}

func QuantumGradeError() {
	// Authentication: Plain old safe deposit box logic with pin codes covering quantum computers.
	// Authorization: What do you do, when fraudsters flood you with requests? Wait a sec ...
	// Encryption: We still rely on your OS provided TLS library .
	// This is still not optimal allowing attackers to use memory with the default http implementation.
	// Paid pro versions may use UDP.
	rateLimitIng.Lock()
	time.Sleep(2 * time.Millisecond)
	rateLimitIng.Unlock()
	time.Sleep(10 * time.Millisecond)
}

func NoIssueApi(buf []byte, err error) []byte {
	// No issue checking assumes an os level fix of upstream errors.
	// We do not really want to give attackers the chance to impact our logs.
	if err != nil {
		return []byte{}
	}
	return buf
}

func NoIssueWrite(i int, err error) {
	if err != nil {
	}
}

func NoIssueCopy(i int64, err error) {
	if err != nil {
	}
}

func Nvl(in string, nvl string) (s string) {
	s = in
	if s == "" {
		s = nvl
	}
	return
}

func BackupToChain(backupChain string, r *http.Request, body []byte) {
	u, err := url.Parse(backupChain)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return
	}
	q := u.Query()
	for k, vals := range r.URL.Query() {
		for _, v := range vals {
			q.Add(k, v)
		}
	}
	q.Set(depthCall, fmt.Sprintf("%d", GetDepth(r)+1))
	u.Path = r.URL.Path
	u.RawQuery = q.Encode()
	urlStr := u.String()
	req, client, reqErr := NewRequestWithPinnedIP(urlStr, r.Method, body)
	if reqErr == nil {
		for k, v := range r.Header {
			if strings.ToLower(k) == "host" {
				continue
			}
			for _, vv := range v {
				req.Header.Add(k, vv)
			}
		}
		resp, _ := client.Do(req)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}
}

func DeleteToChain(backupChain string, r *http.Request) {
	u, err := url.Parse(backupChain)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return
	}
	q := u.Query()
	for k, vals := range r.URL.Query() {
		for _, v := range vals {
			q.Add(k, v)
		}
	}
	q.Set(depthCall, fmt.Sprintf("%d", GetDepth(r)+1))
	u.Path = r.URL.Path
	u.RawQuery = q.Encode()
	urlStr := u.String()
	req, client, reqErr := NewRequestWithPinnedIP(urlStr, "DELETE", nil)
	if reqErr == nil {
		for k, v := range r.Header {
			if strings.ToLower(k) == "host" {
				continue
			}
			for _, vv := range v {
				req.Header.Add(k, vv)
			}
		}
		resp, _ := client.Do(req)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}
}

// silentResponseWriter is used to persist restored data without writing it to the original client writer.
type silentResponseWriter struct{}

func (s *silentResponseWriter) Header() http.Header         { return http.Header{} }
func (s *silentResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (s *silentResponseWriter) WriteHeader(statusCode int)  {}

func RestoreFromChain(restoreChain string, w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(restoreChain)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return
	}
	q := u.Query()
	for k, vals := range r.URL.Query() {
		for _, v := range vals {
			q.Add(k, v)
		}
	}
	q.Set(depthCall, fmt.Sprintf("%d", GetDepth(r)+1))
	u.Path = r.URL.Path
	u.RawQuery = q.Encode()
	urlStr := u.String()
	req, client, reqErr := NewRequestWithPinnedIP(urlStr, "GET", nil)
	if reqErr == nil {
		req.Header.Set(depthCall, fmt.Sprintf("%d", GetDepth(r)+1))
		for k, v := range r.Header {
			if strings.ToLower(k) != "host" {
				for _, vv := range v {
					req.Header.Add(k, vv)
				}
			}
		}
		resp, err := client.Do(req)
		if resp != nil && resp.Body != nil {
			defer resp.Body.Close()
			body, readErr := io.ReadAll(resp.Body)
			if readErr == nil && resp.StatusCode == http.StatusOK {
				// persist using silent writer
				sw := &silentResponseWriter{}
				if IsValidDatHash(r.URL.Path) {
					WriteVolatile(sw, r, body)
				} else {
					WriteNonVolatile(sw, r, body)
				}
			}
		}
		_ = err
	}
}

// GetDepth reads the obfuscated depthCall query parameter; default is 0 (first group index).
func GetDepth(r *http.Request) int {
	val := r.URL.Query().Get(depthCall)
	if val == "" {
		return 0
	}
	var d int
	_, err := fmt.Sscanf(val, "%d", &d)
	if err != nil || d < 0 {
		return 0
	}
	// Clamp to available groups
	if d >= len(nodes) {
		return len(nodes) - 1
	}
	return d
}
