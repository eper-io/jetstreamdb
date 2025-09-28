package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Data directory constant
const DATA = "/data"

// File size limit constant (1 megabyte)
const MAX_FILE_SIZE = 1024 * 1024

// Watchdog cleanup interval (60 seconds)
const WATCHDOG_INTERVAL = 60 * time.Second

// Watchdog timeout period for restore
const WATCHDOG_TIMEOUT = 60 * time.Second

// Global startup time
var startupTime = time.Now()

// File age threshold for cleanup (60 seconds)
// Global backup IP array
var BACKUP_IPS = []string{
	"http://18.209.57.108@hour.schmied.us",
}

// Helper: choose random backup IP
func getRandomBackupIP() string {
	return BACKUP_IPS[int(time.Now().UnixNano())%len(BACKUP_IPS)]
}

// Helper: extract domain name from https://ip@name
func extractDomain(url string) string {
	parts := strings.Split(url, "@")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// jetstream_backup: PUT file to backup IP at /sha256.dat
func jetstream_backup(filePath, sha256Name string) {
	backupIP := getRandomBackupIP()
	var urlStr string
	if strings.Contains(backupIP, "@") {
		urlStr = fmt.Sprintf("%s/%s", strings.Split(backupIP, "@")[0], sha256Name)
	} else {
		urlStr = fmt.Sprintf("%s/%s", backupIP, sha256Name)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()

	req, err := http.NewRequest("PUT", urlStr, file)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{
		Timeout: 30 * time.Second, // Add timeout for backup operations
	}
	// TLS verification if needed
	if strings.HasPrefix(backupIP, "https://") && strings.Contains(backupIP, "@") {
		domain := extractDomain(backupIP)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: domain},
		}
		client.Transport = tr
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}
// Global backup IP array
const FILE_AGE_THRESHOLD = 60 * time.Second

// JetStream volatile storage function
func jetstream_volatile(path string, queryStrings []string, method string, httpParams []string, inputBuffer []byte, inputSize int, outputBuffer *[]byte, outputSize *int) {
	// Validate path format /sha256.dat
	if !strings.HasPrefix(path, "/") || !strings.HasSuffix(path, ".dat") {
		// Invalid path format - return empty string
		*outputBuffer = []byte("")
		*outputSize = 0
		return
	}

	// Extract hash from path
	pathHash := strings.TrimPrefix(path, "/")
	pathHash = strings.TrimSuffix(pathHash, ".dat")
	
	// Validate hash format (64 hex characters for SHA256)
	if len(pathHash) != 64 {
		*outputBuffer = []byte("")
		*outputSize = 0
		return
	}

	// Construct full file path
	fullPath := filepath.Join(DATA, pathHash+".dat")

	// Helper function to format response path with security measures
	formatResponsePath := func(responsePath string) string {
		// Look for format parameter in query strings
		for _, queryParam := range queryStrings {
			if strings.HasPrefix(queryParam, "format=") {
				formatTemplate := strings.TrimPrefix(queryParam, "format=")
				
				// Security: Limit format template length to prevent buffer overflow
				const maxFormatLength = 2048
				if len(formatTemplate) > maxFormatLength {
					return responsePath // Return original path if template too long
				}
				
				// URL decode the format template
				decodedTemplate, err := url.QueryUnescape(formatTemplate)
				if err != nil {
					// If decoding fails, use original template
					decodedTemplate = formatTemplate
				}
				
				// Security: Limit decoded template length
				if len(decodedTemplate) > maxFormatLength {
					return responsePath
				}
				
				// Security: Validate that template doesn't contain dangerous patterns
				// Prevent potential injection attacks
				if strings.Contains(decodedTemplate, "\x00") || 
				   strings.Contains(decodedTemplate, "\r") || 
				   strings.Contains(decodedTemplate, "\n") {
					return responsePath
				}
				
				// Replace placeholders with the response path
				formatted := strings.ReplaceAll(decodedTemplate, "%s", responsePath)
				formatted = strings.ReplaceAll(formatted, "%25s", responsePath)
				formatted = strings.ReplaceAll(formatted, "*", responsePath)
				
				// Security: Limit final formatted result length
				const maxResultLength = 4096
				if len(formatted) > maxResultLength {
					return responsePath // Return original path if result too long
				}
				
				return formatted
			}
		}
		// No format parameter found, return original path
		return responsePath
	}


	switch method {
	case "PUT", "POST":
		// Check input buffer size limit
		if inputSize > MAX_FILE_SIZE {
			*outputBuffer = []byte("")
			*outputSize = 0
			return
		}

		// Check for channel write: read existing file content first (matching main.c logic)
		existingContent := make([]byte, 512)
		existingContent[0] = 0
		
		if file, err := os.Open(fullPath); err == nil {
			bytesRead, _ := file.Read(existingContent)
			file.Close()
			if bytesRead > 0 {
				existingContent = existingContent[:bytesRead]
				existingContentStr := string(existingContent)
				
				// Check if existing content is a write channel
				if strings.HasPrefix(existingContentStr, "Write channel /") {
					// Check if we're trying to create the same channel content
					if inputSize > 15 && strings.HasPrefix(string(inputBuffer), "Write channel /") &&
						string(inputBuffer) == existingContentStr {
						// Creating the same channel, return channel path
						result := formatResponsePath(path)
						*outputBuffer = []byte(result)
						*outputSize = len(result)
						return
					} else {
						// Writing to existing channel, return channel content for redirection
						*outputBuffer = existingContent
						*outputSize = len(existingContent)
						return
					}
				}
				
				// Check if existing content is an append channel
				if strings.HasPrefix(existingContentStr, "Append channel /") {
					// Check if we're trying to create the same channel content
					if inputSize > 16 && strings.HasPrefix(string(inputBuffer), "Append channel /") &&
						string(inputBuffer) == existingContentStr {
						// Creating the same channel, return channel path
						result := formatResponsePath(path)
						*outputBuffer = []byte(result)
						*outputSize = len(result)
						return
					} else {
						// Writing to existing channel, return channel content for redirection
						*outputBuffer = existingContent
						*outputSize = len(existingContent)
						return
					}
				}
				
				// Check if existing content is a read channel
				if strings.HasPrefix(existingContentStr, "Read channel /") {
					// Read channels cannot be written to, return empty string
					*outputBuffer = []byte("")
					*outputSize = 0
					return
				}
			}
		}

		// Check for append=1 query parameter
		appendMode := false
		for _, queryParam := range queryStrings {
			if queryParam == "append=1" {
				appendMode = true
				break
			}
		}

		// For append mode, check existing file size + new content size
		if appendMode {
			if stat, err := os.Stat(fullPath); err == nil {
				if stat.Size()+int64(inputSize) > MAX_FILE_SIZE {
					*outputBuffer = []byte("")
					*outputSize = 0
					return
				}
			}
		}

		var file *os.File
		var err error
		
		if appendMode {
			// Open file with O_APPEND for appending, create if doesn't exist
			file, err = os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		} else {
			// Create or truncate file and save content (normal mode)
			file, err = os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		}
		
		if err != nil {
			*outputBuffer = []byte("")
			*outputSize = 0
			return
		}
		defer file.Close()

		_, err = file.Write(inputBuffer)
		if err != nil {
			*outputBuffer = []byte("")
			*outputSize = 0
			return
		}

		// Update file modification time to reset watchdog timer
		currentTime := time.Now()
		os.Chtimes(fullPath, currentTime, currentTime)

		// Check if we just created a write channel (matching main.c logic)
		if inputSize > 15 && strings.HasPrefix(string(inputBuffer), "Write channel /") {
			// For write channel creation, return the channel path (not the content)
			result := formatResponsePath(path)
			*outputBuffer = []byte(result)
			*outputSize = len(result)
		} else {
			// For normal file creation, return the path
			result := formatResponsePath(path)
			*outputBuffer = []byte(result)
			*outputSize = len(result)
		}

	case "GET":
		// Read file content first to check for channels
		content, err := os.ReadFile(fullPath)
		if err != nil {
			// File doesn't exist - this is expected, return empty string without logging
			*outputBuffer = []byte("")
			*outputSize = 0
			return
		}

		// Check file size to prevent memory exhaustion
		if len(content) > MAX_FILE_SIZE {
			*outputBuffer = []byte("")
			*outputSize = 0
			return
		}

		// Check if content is a write channel, return empty string if so (matching main.c)
		if strings.HasPrefix(string(content), "Write channel /") {
			*outputBuffer = []byte("")
			*outputSize = 0
			return
		}
		
		// Check if content is an append channel, return empty string if so (matching main.c)
		if strings.HasPrefix(string(content), "Append channel /") {
			*outputBuffer = []byte("")
			*outputSize = 0
			return
		}
		
		// Check if content is a read channel, return channel content for redirection (matching main.c)
		if strings.HasPrefix(string(content), "Read channel /") {
			// For read channels, return the channel content for redirection
			*outputBuffer = content
			*outputSize = len(content)
			return
		}

		// Check for take=1 query parameter
		takeMode := false
		for _, queryParam := range queryStrings {
			if queryParam == "take=1" {
				takeMode = true
				break
			}
		}

		if takeMode {
			// Take operation: read content then delete file atomically (matching main.c)
			// Check if content is a write channel, return empty string if so
			if strings.HasPrefix(string(content), "Write channel /") {
				*outputBuffer = []byte("")
				*outputSize = 0
				return
			}
			// Check if content is a read channel, return channel content for redirection
			if strings.HasPrefix(string(content), "Read channel /") {
				// For read channels, return the channel content for redirection
				// Don't delete the file in take mode for read channels
				*outputBuffer = content
				*outputSize = len(content)
				return
			}
			// Update file modification time before deletion
			currentTime := time.Now()
			os.Chtimes(fullPath, currentTime, currentTime)
			// Delete the file after successful read
			err = os.Remove(fullPath)
			if err != nil {
				// If deletion fails, still return the content we read
				*outputBuffer = content
				*outputSize = len(content)
				return
			}

			// Successfully read and deleted - return content
			*outputBuffer = content
			*outputSize = len(content)
		} else {
			// Normal GET operation: read file content without deletion
			// Update file modification time after successful read
			currentTime := time.Now()
			os.Chtimes(fullPath, currentTime, currentTime)
			*outputBuffer = content
			*outputSize = len(content)
		}

	case "DELETE":
		// Check if file exists and read content to check for channels
		content, err := os.ReadFile(fullPath)
		if err != nil {
			// File doesn't exist - return empty
			*outputBuffer = []byte("")
			*outputSize = 0
			return
		}

		// Check if file is a write channel before deletion (matching main.c)
		if strings.HasPrefix(string(content), "Write channel /") {
			*outputBuffer = []byte("")
			*outputSize = 0
			return
		}
		// Prevent deletion of append channels
		if strings.HasPrefix(string(content), "Append channel /") {
			*outputBuffer = []byte("")
			*outputSize = 0
			return
		}
		// Prevent deletion of read channels
		if strings.HasPrefix(string(content), "Read channel /") {
			*outputBuffer = []byte("")
			*outputSize = 0
			return
		}

		// Normal file - proceed with deletion
		err = os.Remove(fullPath)
		if err != nil && !os.IsNotExist(err) {
			*outputBuffer = []byte("")
			*outputSize = 0
			return
		}

		// Return formatted path
		result := formatResponsePath(path)
		*outputBuffer = []byte(result)
		*outputSize = len(result)

	default:
		// Unsupported method
		*outputBuffer = []byte("")
		*outputSize = 0
	}
}

// JetStream non-volatile storage function - filters calls to jetstream_volatile
func jetstream_nonvolatile(path string, queryStrings []string, method string, httpParams []string, inputBuffer []byte, inputSize int, outputBuffer *[]byte, outputSize *int) {
	switch method {
	case "GET", "HEAD":
		// Forward GET and HEAD requests directly to jetstream_volatile
		jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)
		return

	case "PUT", "POST":
		// Calculate SHA256 hash of input content
		hash := sha256.Sum256(inputBuffer)
		contentHash := hex.EncodeToString(hash[:])
		contentPath := "/" + contentHash + ".dat"

		// Check if path is NULL, empty, or /
		if path == "" || path == "/" || strings.ToUpper(path) == "NULL" {
			// Use content hash as path
			jetstream_volatile(contentPath, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)
			return
		}

		// Validate if path is in /sha256.dat format
		if strings.HasPrefix(path, "/") && strings.HasSuffix(path, ".dat") {
			pathHash := strings.TrimPrefix(path, "/")
			pathHash = strings.TrimSuffix(pathHash, ".dat")
			
			// Check if path hash is valid (64 hex characters)
			if len(pathHash) == 64 {
				// Check if path hash matches content hash
				if pathHash == contentHash {
					// Hash matches - call jetstream_volatile with this path
					jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)
					return
				}
			}
		}

		// Path doesn't match content hash - check existing file
		// Construct full file path based on request path
		var existingFilePath string
		if strings.HasPrefix(path, "/") && strings.HasSuffix(path, ".dat") {
			pathHash := strings.TrimPrefix(path, "/")
			pathHash = strings.TrimSuffix(pathHash, ".dat")
			if len(pathHash) == 64 {
				existingFilePath = filepath.Join(DATA, pathHash+".dat")
			}
		}

		if existingFilePath != "" {
			// Try to read existing file and get its hash
			existingContent, err := os.ReadFile(existingFilePath)
			if err == nil {
				// File exists - calculate its hash
				existingHash := sha256.Sum256(existingContent)
				existingHashStr := hex.EncodeToString(existingHash[:])
				
				// Extract hash from path for comparison
				pathHash := strings.TrimPrefix(path, "/")
				pathHash = strings.TrimSuffix(pathHash, ".dat")
				
				if existingHashStr == pathHash {
					// Hash matches existing content - ignore PUT request
					*outputBuffer = []byte("")
					*outputSize = 0
					return
				}
			}
		}

		// Content hash doesn't match path - store as KV pair using jetstream_volatile
		jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)

	case "DELETE":
		// Check existing file and compare hash
		var existingFilePath string
		if strings.HasPrefix(path, "/") && strings.HasSuffix(path, ".dat") {
			pathHash := strings.TrimPrefix(path, "/")
			pathHash = strings.TrimSuffix(pathHash, ".dat")
			if len(pathHash) == 64 {
				existingFilePath = filepath.Join(DATA, pathHash+".dat")
			}
		}

		if existingFilePath != "" {
			// Try to read existing file and get its hash
			existingContent, err := os.ReadFile(existingFilePath)
			if err == nil {
				// File exists - calculate its hash
				existingHash := sha256.Sum256(existingContent)
				existingHashStr := hex.EncodeToString(existingHash[:])
				
				// Extract hash from path for comparison
				pathHash := strings.TrimPrefix(path, "/")
				pathHash = strings.TrimSuffix(pathHash, ".dat")
				
				if existingHashStr == pathHash {
					// Hash matches existing content - ignore DELETE request
					*outputBuffer = []byte("")
					*outputSize = 0
					return
				}
			}
		}

		// Content hash doesn't match or file doesn't exist - forward to jetstream_volatile
		jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)

	default:
		// Unsupported method
		*outputBuffer = []byte("")
		*outputSize = 0
	}
}

// JetStream local storage function
func jetstream_local(path string, queryStrings []string, method string, httpParams []string, inputBuffer []byte, inputSize int, outputBuffer *[]byte, outputSize *int) {
	// Calculate SHA256 hash of input buffer
	hash := sha256.Sum256(inputBuffer)
	expectedHash := hex.EncodeToString(hash[:])
	
	// Check for special paths first (NULL, empty, or /)
	if method == "PUT" && (path == "/" || path == "" || strings.ToUpper(path) == "NULL") {
		// Special PUT case - use non-volatile storage
		jetstream_nonvolatile(path, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)
		return
	}
	
	// Check if path is in format /sha256.dat
	if strings.HasPrefix(path, "/") && strings.HasSuffix(path, ".dat") {
		// Extract hash from path (remove leading "/" and trailing ".dat")
		pathHash := strings.TrimPrefix(path, "/")
		pathHash = strings.TrimSuffix(pathHash, ".dat")
		
		// For PUT/POST, check if hash matches content
		if method == "PUT" || method == "POST" {
			if pathHash == expectedHash {
				// Hash matches - use non-volatile storage
				jetstream_nonvolatile(path, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)
			} else {
				// Hash doesn't match - use volatile storage
				jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)
			}
		} else {
			// For GET, DELETE, HEAD - always use non-volatile storage for hash validation
			jetstream_nonvolatile(path, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)
		}
	} else {
		// Path not in expected format - use volatile storage
		jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)
	}
}

// JetStream restore function
func jetstream_restore(path string, queryStrings []string, method string, httpParams []string, inputBuffer []byte, inputSize int, outputBuffer *[]byte, outputSize *int) {
	// For GET requests to /sha256.dat files, try to fetch from backup IPs if file is missing
	if method == "GET" && strings.HasPrefix(path, "/") && strings.HasSuffix(path, ".dat") {
		// First check if file exists locally
		fullPath := filepath.Join(DATA, filepath.Base(path))
		if _, err := os.Stat(fullPath); err == nil {
			// File exists locally, use jetstream_local
			jetstream_local(path, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)
			return
		}
		
		// File doesn't exist locally, try to restore from backup if within timeout
		if time.Since(startupTime) < WATCHDOG_TIMEOUT {
			// Try each backup IP randomly
			indices := rand.Perm(len(BACKUP_IPS))
			for _, idx := range indices {
				backupIP := BACKUP_IPS[idx]
				var urlStr string
				if strings.Contains(backupIP, "@") {
					urlStr = fmt.Sprintf("%s%s", strings.Split(backupIP, "@")[0], path)
				} else {
					urlStr = fmt.Sprintf("%s%s", backupIP, path)
				}

				client := &http.Client{Timeout: 10 * time.Second}
				// TLS verification if needed
				if strings.HasPrefix(backupIP, "https://") && strings.Contains(backupIP, "@") {
					domain := extractDomain(backupIP)
					tr := &http.Transport{
						TLSClientConfig: &tls.Config{ServerName: domain},
					}
					client.Transport = tr
				}
				
				resp, err := client.Get(urlStr)
				if err != nil || resp.StatusCode != http.StatusOK {
					if resp != nil {
						resp.Body.Close()
					}
					continue
				}
				
				data, err := io.ReadAll(io.LimitReader(resp.Body, MAX_FILE_SIZE))
				resp.Body.Close()
				if err != nil || len(data) == 0 {
					continue
				}
				
				// Save to /data/sha256.dat
				shaFile := filepath.Join(DATA, filepath.Base(path))
				err = os.WriteFile(shaFile, data, 0644)
				if err != nil {
					continue
				}
				
				// Successfully restored, return the data
				*outputBuffer = data
				*outputSize = len(data)
				return
			}
		}
	}
	
	// Pass through to jetstream_local for normal operation or if restore failed
	jetstream_local(path, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)
}

// JetStream remote function
func jetstream_remote(path string, queryStrings []string, method string, httpParams []string, inputBuffer []byte, inputSize int, outputBuffer *[]byte, outputSize *int) {
	// Pass through to jetstream_restore
	jetstream_restore(path, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)
}

// JetStream application function
func jetstream_application(path string, queryStrings []string, method string, httpParams []string, inputBuffer []byte, inputSize int, outputBuffer *[]byte, outputSize *int) {

	// Check for burst parameter
	for _, queryParam := range queryStrings {
		if queryParam == "burst=1" {
			if method == "GET" {
				// Burst GET: call jetstream_remote to get list of chunk hashes
				var listBuffer []byte
				var listSize int
				jetstream_remote(path, queryStrings, method, httpParams, inputBuffer, inputSize, &listBuffer, &listSize)
				
				if listSize == 0 {
					*outputBuffer = []byte("")
					*outputSize = 0
					return
				}
				
				// Parse newline-separated list of /sha256.dat values
				hashList := strings.Split(string(listBuffer), "\n")
				var concatenatedContent []byte
				
				// Limit number of hash entries to prevent memory exhaustion
				const maxHashEntries = 1000
				if len(hashList) > maxHashEntries {
					hashList = hashList[:maxHashEntries]
				}
				
				for _, hashPath := range hashList {
					hashPath = strings.TrimSpace(hashPath)
					if hashPath == "" {
						continue
					}
					
					// Validate hash path format
					if !strings.HasPrefix(hashPath, "/") || !strings.HasSuffix(hashPath, ".dat") {
						continue
					}
					
					// Extract hash and validate length
					hash := strings.TrimPrefix(hashPath, "/")
					hash = strings.TrimSuffix(hash, ".dat")
					if len(hash) != 64 {
						continue
					}
					
					// Call jetstream_remote to read each chunk file
					var chunkBuffer []byte
					var chunkSize int
					jetstream_remote(hashPath, []string{}, "GET", httpParams, []byte{}, 0, &chunkBuffer, &chunkSize)
					
					if chunkSize > 0 {
						// Check for potential memory exhaustion
						if len(concatenatedContent)+chunkSize > MAX_FILE_SIZE*10 {
							// Prevent excessive memory usage (10x file size limit)
							break
						}
						concatenatedContent = append(concatenatedContent, chunkBuffer...)
					}
				}
				
				*outputBuffer = concatenatedContent
				*outputSize = len(concatenatedContent)
				return
				
			} else if method == "PUT" || method == "POST" {
				// Burst PUT/POST: split input into 4096-byte blocks
				const blockSize = 4096
				var hashPaths []string
				
				// Process input buffer in 4096-byte chunks with bounds checking
				for offset := 0; offset < inputSize; offset += blockSize {
					end := offset + blockSize
					if end > inputSize {
						end = inputSize
					}
					
					// Bounds check to prevent slice out of range
					if offset >= len(inputBuffer) {
						break
					}
					if end > len(inputBuffer) {
						end = len(inputBuffer)
					}
					
					block := inputBuffer[offset:end]
					
					// Call jetstream_remote to store this block
					var blockHashBuffer []byte
					var blockHashSize int
					jetstream_remote("/", []string{}, method, httpParams, block, len(block), &blockHashBuffer, &blockHashSize)
					
					if blockHashSize > 0 {
						hashPath := strings.TrimSpace(string(blockHashBuffer))
						if hashPath != "" {
							hashPaths = append(hashPaths, hashPath)
						}
					}
				}
				
				// Create newline-separated list of hash paths
				// Limit number of hash paths to prevent memory exhaustion
				const maxHashPaths = 1000
				if len(hashPaths) > maxHashPaths {
					hashPaths = hashPaths[:maxHashPaths]
				}
				
				hashList := strings.Join(hashPaths, "\n")
				hashListBytes := []byte(hashList)
				
				// Store the hash list itself using jetstream_remote
				jetstream_remote(path, queryStrings, method, httpParams, hashListBytes, len(hashListBytes), outputBuffer, outputSize)
				return
			}
		}
	}
	
	// Call jetstream_remote for normal operation
	jetstream_remote(path, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)
	
	// For GET operations, check if the result is empty and attempt restore if within timeout
	if method == "GET" && *outputSize == 0 && time.Since(startupTime) < WATCHDOG_TIMEOUT {
		// Attempt restore for failed GET
		var restoreBuffer []byte
		var restoreSize int
		jetstream_restore(path, queryStrings, method, httpParams, inputBuffer, inputSize, &restoreBuffer, &restoreSize)
		if restoreSize > 0 {
			*outputBuffer = restoreBuffer
			*outputSize = restoreSize
			// Don't return here, continue with channel processing
		}
	}
	
	// Check if the response is a write channel for PUT/POST operations (matching main.c logic)
	if (method == "PUT" || method == "POST") && *outputSize > 15 {
		response := string(*outputBuffer)
		if strings.HasPrefix(response, "Write channel /") {
			// Extract the target path from "Write channel /sha256.dat"
			targetPath := response[14:] // Skip "Write channel "
			if strings.HasSuffix(targetPath, ".dat") && len(targetPath) == 69 && targetPath[0] == '/' {
				// Check if target file exists for append operations before redirecting
				if strings.Contains(strings.Join(queryStrings, "&"), "append=1") {
					fullPath := filepath.Join(DATA, filepath.Base(targetPath))
					if _, err := os.Stat(fullPath); os.IsNotExist(err) && time.Since(startupTime) < WATCHDOG_TIMEOUT {
						// Target file doesn't exist, try restore first
						var restoreBuffer []byte
						var restoreSize int
						jetstream_restore(targetPath, []string{}, "GET", httpParams, []byte{}, 0, &restoreBuffer, &restoreSize)
					}
				}
				
				// Call jetstream_remote with the redirected path
				jetstream_remote(targetPath, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)
				// Return the channel path to hide the target (format response path)
				result := path
				*outputBuffer = []byte(result)
				*outputSize = len(result)
				return
			}
		}
	}
	
	// Check if the response is an append channel for PUT/POST operations (matching main.c logic)
	if (method == "PUT" || method == "POST") && *outputSize > 16 {
		response := string(*outputBuffer)
		if strings.HasPrefix(response, "Append channel /") {
			// Extract the target path from "Append channel /sha256.dat"
			targetPath := response[15:] // Skip "Append channel "
			if strings.HasSuffix(targetPath, ".dat") && len(targetPath) == 69 && targetPath[0] == '/' {
				// Check if target file exists before appending
				fullPath := filepath.Join(DATA, filepath.Base(targetPath))
				if _, err := os.Stat(fullPath); os.IsNotExist(err) && time.Since(startupTime) < WATCHDOG_TIMEOUT {
					// Target file doesn't exist, try restore first
					var restoreBuffer []byte
					var restoreSize int
					jetstream_restore(targetPath, []string{}, "GET", httpParams, []byte{}, 0, &restoreBuffer, &restoreSize)
				}
				
				// Build query string with append=1 parameter
				var appendQueryStrings []string
				if len(queryStrings) > 0 && queryStrings[0] != "" {
					appendQueryStrings = []string{queryStrings[0] + "&append=1"}
				} else {
					appendQueryStrings = []string{"append=1"}
				}
				// Append remaining query strings
				for i := 1; i < len(queryStrings); i++ {
					appendQueryStrings = append(appendQueryStrings, queryStrings[i])
				}
				
				// Call jetstream_remote with the redirected path and append=1
				jetstream_remote(targetPath, appendQueryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)
				// Return the channel path to hide the target
				result := path
				*outputBuffer = []byte(result)
				*outputSize = len(result)
				return
			}
		}
	}
	
	// Check if the response is a read channel for GET operations (matching main.c logic)
	if method == "GET" && *outputSize > 14 {
		response := string(*outputBuffer)
		if strings.HasPrefix(response, "Read channel /") {
			// Extract the target path from "Read channel /sha256.dat"
			targetPath := response[13:] // Skip "Read channel "
			if strings.HasSuffix(targetPath, ".dat") && len(targetPath) == 69 && targetPath[0] == '/' {
				// Call jetstream_remote with the redirected path to get target file content
				jetstream_remote(targetPath, queryStrings, method, httpParams, inputBuffer, inputSize, outputBuffer, outputSize)
				
				// If read channel target failed and we got empty result, try restore
				if *outputSize == 0 && time.Since(startupTime) < WATCHDOG_TIMEOUT {
					var restoreBuffer []byte
					var restoreSize int
					jetstream_restore(targetPath, queryStrings, method, httpParams, inputBuffer, inputSize, &restoreBuffer, &restoreSize)
					if restoreSize > 0 {
						*outputBuffer = restoreBuffer
						*outputSize = restoreSize
					}
				}
				// Do NOT format response path - return the target file content directly
				return
			}
		}
	}
}

// HTTP request handler
func httpHandler(w http.ResponseWriter, r *http.Request) {
	// Read request body with size limit to prevent memory exhaustion
	body, err := io.ReadAll(io.LimitReader(r.Body, MAX_FILE_SIZE))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Extract query parameters
	queryParams := make([]string, 0)
	for key, values := range r.URL.Query() {
		for _, value := range values {
			queryParams = append(queryParams, key+"="+value)
		}
	}

	// Extract HTTP headers as parameters
	httpParams := make([]string, 0)
	for key, values := range r.Header {
		for _, value := range values {
			httpParams = append(httpParams, key+"="+value)
		}
	}

	// Prepare output buffer
	var outputBuffer []byte
	var outputSize int

	// Call jetstream_application
	jetstream_application(
		r.URL.Path,
		queryParams,
		r.Method,
		httpParams,
		body,
		len(body),
		&outputBuffer,
		&outputSize,
	)

	// Write response with bounds checking
	if outputSize > 0 && len(outputBuffer) > 0 {
		// Ensure outputSize doesn't exceed actual buffer length
		actualSize := len(outputBuffer)
		if outputSize > actualSize {
			outputSize = actualSize
		}
		
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(outputSize))
		w.Write(outputBuffer[:outputSize])
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

// Watchdog goroutine for file cleanup
func watchdog() {
	for {
		time.Sleep(WATCHDOG_INTERVAL)
		
		// Walk through data directory and clean up old files
		filepath.Walk(DATA, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Continue walking even if there's an error
			}
			
			// Skip directories
			if info.IsDir() {
				return nil
			}
			
			// Check if file is older than threshold
			if time.Since(info.ModTime()) > FILE_AGE_THRESHOLD {
				// Delete the file
				os.Remove(path)
			} else {
				// Not deleted, backup
				base := filepath.Base(path)
				if strings.HasSuffix(base, ".dat") && len(base) == 68 {
					sha256Name := base
					jetstream_backup(path, sha256Name)
				}
			}
			
			return nil
		})
		
		// Silently continue on errors
	}
}

// JetStream server function
func jetstream_server() {
	// Ensure data directory exists
	err := os.MkdirAll(DATA, 0755)
	if err != nil {
		log.Fatalf("Failed to create data directory %s: %v", DATA, err)
	}
	
	// Start watchdog goroutine
	go watchdog()
	
	// Set up HTTP handler
	http.HandleFunc("/", httpHandler)

	// Check if TLS certificates exist
	keyPath := "/etc/ssl/jetstream.key"
	certPath := "/etc/ssl/jetstream.crt"

	if _, err := os.Stat(keyPath); err == nil {
		if _, err := os.Stat(certPath); err == nil {
			// TLS certificates exist, use HTTPS on port 443
			
			// Validate certificates before starting server
			_, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err == nil {
				// Create TLS configuration
				tlsConfig := &tls.Config{
					MinVersion: tls.VersionTLS12,
				}

				server := &http.Server{
					Addr:      ":443",
					TLSConfig: tlsConfig,
					ReadTimeout:  10 * time.Second,
					WriteTimeout: 10 * time.Second,
				}

				fmt.Println("Starting HTTPS server on port 443")
				log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
			}
		}
	}

	// No TLS certificates or TLS validation failed, use HTTP on port 7777
	server := &http.Server{
		Addr:         ":7777",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	
	fmt.Println("Starting HTTP server on port 7777")
	log.Fatal(server.ListenAndServe())
}

func main() {
	fmt.Println("JetStream Database Server")
	jetstream_server()
}