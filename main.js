const fs = require('fs');
const pathModule = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const url = require('url');
const querystring = require('querystring');

// Constants
const MAX_FILE_SIZE = 1024 * 1024; // 1 MB
const WATCHDOG_INTERVAL = 60000; // 60 seconds
const DATA_DIR = '/data';
const CHUNK_SIZE = 4096;

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Helper function to calculate SHA256 hash
function calculateSHA256(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

// Helper function to format response path
function formatResponsePath(path, queryStrings) {
    for (const queryParam of queryStrings) {
        if (queryParam.startsWith('format=')) {
            const formatValue = decodeURIComponent(queryParam.substring(7));
            // Replace %s, %25s, or * with the path
            const formatted = formatValue.replace(/%25s|%s|\*/g, path);
            
            // Security check: limit formatted response length
            if (formatted.length > 2048) {
                return path; // Return original path if result too long
            }
            
            return formatted;
        }
    }
    return path;
}

// Helper function to update file modification time
function touchFile(filePath) {
    try {
        const now = new Date();
        fs.utimesSync(filePath, now, now);
    } catch (err) {
        // Ignore errors
    }
}

// JetStream volatile function
function jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer, callback) {
    // Validate path format: must be /sha256.dat
    if (!path.startsWith('/') || !path.endsWith('.dat') || path.length !== 69) {
        return callback('');
    }

    const hash = path.substring(1, 65); // Extract hash part
    if (!/^[a-f0-9]{64}$/.test(hash)) {
        return callback('');
    }

    const fullPath = pathModule.join(DATA_DIR, path.substring(1));

    switch (method) {
        case 'PUT':
        case 'POST':
            // Check input buffer size limit
            if (inputBuffer.length > MAX_FILE_SIZE) {
                return callback('');
            }

            // Check for channel write: read existing file content first
            try {
                const existingContent = fs.readFileSync(fullPath);
                const existingContentStr = existingContent.toString();
                
                // Check if existing content is a write channel
                if (existingContentStr.startsWith('Write channel /')) {
                    // Check if we're trying to create the same channel content
                    if (inputBuffer.toString().startsWith('Write channel /') &&
                        inputBuffer.toString() === existingContentStr) {
                        // Creating the same channel, return channel path
                        return callback(formatResponsePath(path, queryStrings));
                    } else {
                        // Writing to existing channel, return channel content for redirection
                        return callback(existingContentStr);
                    }
                }
                
                // Check if existing content is an append channel
                if (existingContentStr.startsWith('Append channel /')) {
                    // Check if we're trying to create the same channel content
                    if (inputBuffer.toString().startsWith('Append channel /') &&
                        inputBuffer.toString() === existingContentStr) {
                        // Creating the same channel, return channel path
                        return callback(formatResponsePath(path, queryStrings));
                    } else {
                        // Writing to existing channel, return channel content for redirection
                        return callback(existingContentStr);
                    }
                }
                
                // Check if existing content is a read channel
                if (existingContentStr.startsWith('Read channel /')) {
                    // Read channels cannot be written to, return empty string
                    return callback('');
                }
            } catch (err) {
                // File doesn't exist, continue with normal operation
            }

            // Check for append=1 query parameter
            const appendMode = queryStrings.includes('append=1');
            
            try {
                if (appendMode) {
                    // Append mode: open file with append flag
                    fs.appendFileSync(fullPath, inputBuffer);
                } else {
                    // Normal mode: create or truncate file
                    fs.writeFileSync(fullPath, inputBuffer);
                }

                // Update file modification time to reset watchdog timer
                touchFile(fullPath);

                // Return the formatted path from request
                return callback(formatResponsePath(path, queryStrings));
            } catch (err) {
                return callback('');
            }

        case 'GET':
            try {
                // Read file content first to check for channels
                const content = fs.readFileSync(fullPath);
                
                // Check file size to prevent memory exhaustion
                if (content.length > MAX_FILE_SIZE) {
                    return callback('');
                }

                const contentStr = content.toString();
                
                // Check if content is a write channel, return empty string if so
                if (contentStr.startsWith('Write channel /')) {
                    return callback('');
                }
                
                // Check if content is an append channel, return empty string if so
                if (contentStr.startsWith('Append channel /')) {
                    return callback('');
                }
                
                // Check if content is a read channel, return channel content for redirection
                if (contentStr.startsWith('Read channel /')) {
                    return callback(contentStr);
                }

                // Check for take=1 query parameter
                const takeMode = queryStrings.includes('take=1');

                if (takeMode) {
                    // Take operation: read content then delete file atomically
                    // Check if content is a write channel, return empty string if so
                    if (contentStr.startsWith('Write channel /')) {
                        return callback('');
                    }
                    // Check if content is a read channel, return channel content for redirection
                    if (contentStr.startsWith('Read channel /')) {
                        // For read channels, return the channel content for redirection
                        // Don't delete the file in take mode for read channels
                        return callback(contentStr);
                    }
                    // Update file modification time before deletion
                    touchFile(fullPath);
                    // Delete the file after successful read
                    try {
                        fs.unlinkSync(fullPath);
                    } catch (deleteErr) {
                        // If deletion fails, still return the content we read
                    }
                    return callback(content.toString());
                } else {
                    // Normal GET operation: read file content without deletion
                    // Update file modification time after successful read
                    touchFile(fullPath);
                    return callback(content.toString());
                }
            } catch (err) {
                // File doesn't exist - return empty string
                return callback('');
            }

        case 'DELETE':
            try {
                // Check if file exists and read content to check for channels
                const content = fs.readFileSync(fullPath);
                const contentStr = content.toString();
                
                // Check if file is a write channel before deletion
                if (contentStr.startsWith('Write channel /')) {
                    return callback('');
                }
                // Prevent deletion of append channels
                if (contentStr.startsWith('Append channel /')) {
                    return callback('');
                }
                // Prevent deletion of read channels
                if (contentStr.startsWith('Read channel /')) {
                    return callback('');
                }

                // Normal file - proceed with deletion
                fs.unlinkSync(fullPath);
                return callback(formatResponsePath(path, queryStrings));
            } catch (err) {
                // File doesn't exist - return empty string
                return callback('');
            }

        default:
            return callback('');
    }
}

// JetStream nonvolatile function
function jetstream_nonvolatile(path, queryStrings, method, httpParams, inputBuffer, callback) {
    switch (method) {
        case 'PUT':
        case 'POST':
            // Calculate hash of input buffer
            const contentHash = calculateSHA256(inputBuffer);
            const expectedPath = `/${contentHash}.dat`;
            
            // If path is NULL, empty, or /, use content hash as path
            if (!path || path === '' || path === '/') {
                return jetstream_volatile(expectedPath, queryStrings, method, httpParams, inputBuffer, callback);
            }
            
            // If path matches content hash, store with this path
            if (path === expectedPath) {
                return jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer, callback);
            }
            
            // Otherwise, read existing file and check hash
            const fullPath = pathModule.join(DATA_DIR, path.substring(1));
            try {
                const existingContent = fs.readFileSync(fullPath);
                const existingHash = calculateSHA256(existingContent);
                const existingExpectedPath = `/${existingHash}.dat`;
                
                // If existing content hash matches the path, ignore the PUT (content already stored)
                if (path === existingExpectedPath) {
                    return callback(formatResponsePath(path, queryStrings));
                }
            } catch (err) {
                // File doesn't exist, continue with storage
            }
            
            // Store as key-value pair
            return jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer, callback);
            
        case 'GET':
        case 'HEAD':
            // Forward GET and HEAD requests directly
            return jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer, callback);
            
        case 'DELETE':
            // For DELETE, check if file exists and hash matches path (matching main.c)
            if (!path || path.length !== 69 || !path.startsWith('/') || !path.endsWith('.dat')) {
                return jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer, callback);
            }
            
            const deleteFullPath = pathModule.join(DATA_DIR, path.substring(1));
            try {
                const existingContent = fs.readFileSync(deleteFullPath);
                const existingHash = calculateSHA256(existingContent);
                const existingExpectedPath = `/${existingHash}.dat`;
                
                // If existing content hash matches the path, ignore the DELETE
                if (path === existingExpectedPath) {
                    return callback('');
                }
            } catch (err) {
                // File doesn't exist, continue with deletion
            }
            
            // Hash doesn't match or file doesn't exist, proceed with delete
            return jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer, callback);
            
        default:
            return callback('');
    }
}

// JetStream local function
function jetstream_local(path, queryStrings, method, httpParams, inputBuffer, callback) {
    // Pass transparently to jetstream_nonvolatile (matching main.c)
    jetstream_nonvolatile(path, queryStrings, method, httpParams, inputBuffer, callback);
}

// JetStream restore function
function jetstream_restore(path, queryStrings, method, httpParams, inputBuffer, callback) {
    // Pass through to jetstream_local
    jetstream_local(path, queryStrings, method, httpParams, inputBuffer, callback);
}

// JetStream remote function
function jetstream_remote(path, queryStrings, method, httpParams, inputBuffer, callback) {
    // Pass through to jetstream_restore
    jetstream_restore(path, queryStrings, method, httpParams, inputBuffer, callback);
}

// JetStream application function
function jetstream_application(path, queryStrings, method, httpParams, inputBuffer, callback) {
    // Check for burst parameter
    if (queryStrings.includes('burst=1')) {
        if (method === 'GET') {
            // Burst GET: call jetstream_remote to get list of chunk hashes
            return jetstream_remote(path, queryStrings, method, httpParams, inputBuffer, (listResult) => {
                if (!listResult) {
                    return callback('');
                }
                
                // Parse newline-separated list of /sha256.dat values
                const hashList = listResult.split('\n').filter(hash => hash.trim());
                const contentChunks = [];
                
                // Limit number of hash entries to prevent memory exhaustion
                const maxHashes = Math.min(hashList.length, 1000);
                
                if (maxHashes === 0) {
                    return callback('');
                }
                
                // Process each hash iteratively to avoid stack overflow
                let currentIndex = 0;
                
                function processNextChunk() {
                    if (currentIndex >= maxHashes) {
                        // Join all chunks at once to avoid repeated string concatenation
                        const concatenatedContent = contentChunks.join('');
                        return callback(concatenatedContent);
                    }
                    
                    const hashPath = hashList[currentIndex].trim();
                    currentIndex++;
                    
                    if (hashPath.startsWith('/') && hashPath.endsWith('.dat') && hashPath.length === 69) {
                        jetstream_remote(hashPath, [], 'GET', [], Buffer.alloc(0), (chunkContent) => {
                            if (chunkContent) {
                                contentChunks.push(chunkContent);
                            }
                            // Use setImmediate to prevent stack overflow on large datasets
                            setImmediate(processNextChunk);
                        });
                    } else {
                        // Use setImmediate to prevent stack overflow
                        setImmediate(processNextChunk);
                    }
                }
                
                processNextChunk();
            });
        }
        
        if (method === 'PUT' || method === 'POST') {
            // Burst PUT/POST: split input into 4KB chunks and store each (matching main.c)
            const inputPtr = inputBuffer;
            let remainingInput = inputBuffer.length;
            const sha256List = [];
            
            // Process input in 4096-byte blocks iteratively to avoid stack overflow
            let currentOffset = 0;
            
            function processNextBlock() {
                if (currentOffset >= inputBuffer.length) {
                    // All blocks processed, store the collected SHA256 list
                    const hashList = sha256List.join('\n');
                    const hashListBuffer = Buffer.from(hashList);
                    return jetstream_remote(path, queryStrings, method, httpParams, hashListBuffer, callback);
                }
                
                const blockSize = Math.min(CHUNK_SIZE, inputBuffer.length - currentOffset);
                const block = inputBuffer.slice(currentOffset, currentOffset + blockSize);
                currentOffset += blockSize;
                
                // Store this block via jetstream_remote (use null path like main.c)
                jetstream_remote(null, null, method, httpParams, block, (blockResponse) => {
                    // Add SHA256 path to list if valid
                    if (blockResponse && blockResponse.length > 0) {
                        sha256List.push(blockResponse);
                    }
                    
                    // Use setImmediate to prevent stack overflow on large files
                    setImmediate(processNextBlock);
                });
            }
            
            processNextBlock();
            return;
        }
    }
    
    // Pass transparently to jetstream_remote for non-burst requests (matching main.c)
    jetstream_remote(path, queryStrings, method, httpParams, inputBuffer, (response) => {
        // Check if the response is a write channel for PUT/POST operations (matching main.c)
        if ((method === 'PUT' || method === 'POST') && response && response.length > 15) {
            if (response.startsWith('Write channel /')) {
                // Extract the target path from "Write channel /sha256.dat"
                const targetPath = response.substring(14); // Skip "Write channel "
                const endMarker = targetPath.indexOf('.dat');
                if (endMarker !== -1 && targetPath.length >= 69) {
                    // Validate target path format
                    if (targetPath.startsWith('/') && targetPath.substring(endMarker) === '.dat') {
                        // Call jetstream_remote with the redirected path
                        return jetstream_remote(targetPath, queryStrings, method, httpParams, inputBuffer, (targetResponse) => {
                            // Return the channel path to hide the target (format response path)
                            callback(formatResponsePath(path, queryStrings));
                        });
                    }
                }
            }
        }
        
        // Check if the response is an append channel for PUT/POST operations (matching main.c)
        if ((method === 'PUT' || method === 'POST') && response && response.length > 16) {
            if (response.startsWith('Append channel /')) {
                // Extract the target path from "Append channel /sha256.dat"
                const targetPath = response.substring(15); // Skip "Append channel "
                const endMarker = targetPath.indexOf('.dat');
                if (endMarker !== -1 && targetPath.length >= 69) {
                    // Validate target path format
                    if (targetPath.startsWith('/') && targetPath.substring(endMarker) === '.dat') {
                        // Build query string with append=1 parameter
                        let appendQuery = 'append=1';
                        if (queryStrings && queryStrings.length > 0 && queryStrings[0].length > 0) {
                            appendQuery = queryStrings[0] + '&append=1';
                        }
                        // Create query string array for jetstream_remote
                        const appendQueryArray = [appendQuery];
                        // Call jetstream_remote with the redirected path and append=1
                        return jetstream_remote(targetPath, appendQueryArray, method, httpParams, inputBuffer, (targetResponse) => {
                            // Return the channel path to hide the target
                            callback(formatResponsePath(path, queryStrings));
                        });
                    }
                }
            }
        }
        
        // Check if the response is a read channel for GET operations (matching main.c)
        if (method === 'GET' && response && response.length > 14) {
            if (response.startsWith('Read channel /')) {
                // Extract the target path from "Read channel /sha256.dat"
                const targetPath = response.substring(13); // Skip "Read channel "
                const endMarker = targetPath.indexOf('.dat');
                if (endMarker !== -1 && targetPath.length >= 69) {
                    // Validate target path format
                    if (targetPath.startsWith('/') && targetPath.substring(endMarker) === '.dat') {
                        // Call jetstream_remote with the redirected path to get target file content
                        return jetstream_remote(targetPath, queryStrings, method, httpParams, inputBuffer, callback);
                        // Do NOT call formatResponsePath - return the target file content directly
                    }
                }
            }
        }
        
        // Return the original response
        callback(response);
    });
}

// HTTP request handler
function httpHandler(req, res) {
    let body = Buffer.alloc(0);
    
    req.on('data', (chunk) => {
        if (body.length + chunk.length > MAX_FILE_SIZE) {
            res.writeHead(413, { 'Content-Type': 'text/plain' });
            res.end('Request entity too large');
            return;
        }
        body = Buffer.concat([body, chunk]);
    });
    
    req.on('end', () => {
        const parsedUrl = url.parse(req.url, true);
        const path = parsedUrl.pathname || '/';
        const queryStrings = [];
        
        // Convert query parameters to array format
        for (const [key, value] of Object.entries(parsedUrl.query)) {
            if (Array.isArray(value)) {
                for (const v of value) {
                    queryStrings.push(`${key}=${v}`);
                }
            } else {
                queryStrings.push(`${key}=${value}`);
            }
        }
        
        const method = req.method;
        const httpParams = [];
        
        // Extract HTTP headers as parameters
        for (const [key, value] of Object.entries(req.headers)) {
            httpParams.push(`${key}: ${value}`);
        }
        
        // Call jetstream_application
        jetstream_application(path, queryStrings, method, httpParams, body, (result) => {
            if (result === null || result === undefined) {
                result = '';
            }
            
            res.writeHead(200, {
                'Content-Type': 'text/plain',
                'Content-Length': Buffer.byteLength(result),
                'Connection': 'close'
            });
            res.end(result);
        });
    });
    
    req.on('error', (err) => {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Bad request');
    });
}

// Watchdog function to clean up old files
function watchdog() {
    try {
        const files = fs.readdirSync(DATA_DIR);
        const now = Date.now();
        
        for (const file of files) {
            const filePath = pathModule.join(DATA_DIR, file);
            try {
                const stats = fs.statSync(filePath);
                const ageMs = now - stats.mtime.getTime();
                
                // Delete files older than 60 seconds
                if (ageMs > WATCHDOG_INTERVAL) {
                    fs.unlinkSync(filePath);
                    console.log(`Watchdog cleaned up: ${file}`);
                }
            } catch (err) {
                // Ignore errors for individual files
            }
        }
    } catch (err) {
        console.error('Watchdog error:', err.message);
    }
}

// Start watchdog timer
setInterval(watchdog, WATCHDOG_INTERVAL);

// JetStream server function
function jetstream_server() {
    const tlsKeyPath = '/etc/ssl/jetstream.key';
    const tlsCertPath = '/etc/ssl/jetstream.crt';
    
    // Check if TLS certificates exist
    if (fs.existsSync(tlsKeyPath) && fs.existsSync(tlsCertPath)) {
        // HTTPS server on port 443
        const options = {
            key: fs.readFileSync(tlsKeyPath),
            cert: fs.readFileSync(tlsCertPath)
        };
        
        const httpsServer = https.createServer(options, httpHandler);
        httpsServer.listen(443, () => {
            console.log('JetStreamDB HTTPS server listening on port 443');
        });
        
        httpsServer.on('error', (err) => {
            console.error('HTTPS server error:', err.message);
            // Fallback to HTTP if HTTPS fails
            startHttpServer();
        });
    } else {
        // HTTP server on port 7777
        startHttpServer();
    }
}

function startHttpServer() {
    const httpServer = http.createServer(httpHandler);
    httpServer.listen(7777, () => {
        console.log('JetStreamDB HTTP server listening on port 7777');
    });
    
    httpServer.on('error', (err) => {
        console.error('HTTP server error:', err.message);
    });
}

// Start the server
if (require.main === module) {
    jetstream_server();
}

module.exports = {
    jetstream_volatile,
    jetstream_nonvolatile,
    jetstream_local,
    jetstream_restore,
    jetstream_remote,
    jetstream_application,
    jetstream_server
};