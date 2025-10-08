const fs = require('fs');
const pathModule = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const url = require('url');
const querystring = require('querystring');
const { execSync } = require('child_process');

// Constants
const MAX_FILE_SIZE = 1024 * 1024; // 1 MB
const WATCHDOG_INTERVAL = 60000; // 60 seconds
const WATCHDOG_TIMEOUT = 60000; // 60 seconds for restore timeout
const DATA_DIR = '/data';

// Global startup time
const startupTime = Date.now();

// CHUNK_SIZE will be handled in next step
// Global backup IP array
const BACKUP_IPS = [
    'http://18.209.57.108@hour.schmied.us'
];

// Helper: choose random backup IP
function getRandomBackupIP() {
    return BACKUP_IPS[Math.floor(Math.random() * BACKUP_IPS.length)];
}

// Helper: extract domain name from https://ip@name
function extractDomain(url) {
    const atIdx = url.indexOf('@');
    return atIdx !== -1 ? url.substring(atIdx + 1) : null;
}

// jetstream_backup: PUT file to backup IP at /sha256.dat
function jetstream_backup(filePath, sha256Name) {
    const backupIP = getRandomBackupIP();
    let urlStr = backupIP;
    if (backupIP.includes('@')) {
        urlStr = backupIP.split('@')[0];
    }
    urlStr += '/' + sha256Name;

    const fileStream = fs.createReadStream(filePath);
    const options = url.parse(urlStr);
    options.method = 'PUT';
    options.headers = { 'Content-Type': 'application/octet-stream' };

    // TLS verification if needed
    if (backupIP.startsWith('https://') && backupIP.includes('@')) {
        options.servername = extractDomain(backupIP);
    }

    const req = (options.protocol === 'https:' ? https : http).request(options, (res) => {
        // Consume response to prevent memory leaks
        res.on('data', () => {});
        res.on('end', () => {});
    });
    
    req.on('error', (err) => {
        console.error('Backup request error:', err.message);
    });
    
    fileStream.on('error', (err) => {
        console.error('Backup file stream error:', err.message);
        req.destroy();
    });
    
    fileStream.pipe(req);
    
    // Set timeout for backup operations
    req.setTimeout(30000, () => {
        req.destroy();
    });
}

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
function jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer) {
    // Validate path format: must be /sha256.dat
    if (!path.startsWith('/') || !path.endsWith('.dat') || path.length !== 69) {
        return '';
    }

    const hash = path.substring(1, 65); // Extract hash part
    if (!/^[a-f0-9]{64}$/.test(hash)) {
        return '';
    }

    const fullPath = pathModule.join(DATA_DIR, path.substring(1));

    switch (method) {
        case 'PUT':
        case 'POST':
            // Check input buffer size limit
            if (inputBuffer.length > MAX_FILE_SIZE) {
                return '';
            }

            // Check for channel write: read existing file content first
            try {
                // Yield to event loop before heavy I/O
                process.nextTick(() => {});
                const existingContent = fs.readFileSync(fullPath);
                const existingContentStr = existingContent.toString();
                
                // Check if existing content is a write channel
                if (existingContentStr.startsWith('Write channel /')) {
                    // Check if we're trying to create the same channel content
                    if (inputBuffer.toString().startsWith('Write channel /') &&
                        inputBuffer.toString() === existingContentStr) {
                        // Creating the same channel, return channel path
                        return formatResponsePath(path, queryStrings);
                    } else {
                        // Writing to existing channel, return channel content for redirection
                        return existingContentStr;
                    }
                }
                
                // Check if existing content is an append channel
                if (existingContentStr.startsWith('Append channel /')) {
                    // Check if we're trying to create the same channel content
                    if (inputBuffer.toString().startsWith('Append channel /') &&
                        inputBuffer.toString() === existingContentStr) {
                        // Creating the same channel, return channel path
                        return formatResponsePath(path, queryStrings);
                    } else {
                        // Writing to existing channel, return channel content for redirection
                        return existingContentStr;
                    }
                }
                
                // Check if existing content is a read channel
                if (existingContentStr.startsWith('Read channel /')) {
                    // Read channels cannot be written to, return empty string
                    return '';
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
                return formatResponsePath(path, queryStrings);
            } catch (err) {
                return '';
            }

        case 'GET':
            try {
                // Yield to event loop before heavy I/O
                process.nextTick(() => {});
                // Read file content first to check for channels
                const content = fs.readFileSync(fullPath);
                
                // Check file size to prevent memory exhaustion
                if (content.length > MAX_FILE_SIZE) {
                    return '';
                }

                const contentStr = content.toString();
                
                // Check if content is a write channel, return empty string if so
                if (contentStr.startsWith('Write channel /')) {
                    return '';
                }
                
                // Check if content is an append channel, return empty string if so
                if (contentStr.startsWith('Append channel /')) {
                    return '';
                }
                
                // Check if content is a read channel, return channel content for redirection
                if (contentStr.startsWith('Read channel /')) {
                    return contentStr;
                }

                // Check for take=1 query parameter
                const takeMode = queryStrings.includes('take=1');

                if (takeMode) {
                    // Take operation: read content then delete file atomically
                    // Check if content is a write channel, return empty string if so
                    if (contentStr.startsWith('Write channel /')) {
                        return '';
                    }
                    // Check if content is a read channel, return channel content for redirection
                    if (contentStr.startsWith('Read channel /')) {
                        // For read channels, return the channel content for redirection
                        // Don't delete the file in take mode for read channels
                        return contentStr;
                    }
                    // Update file modification time before deletion
                    touchFile(fullPath);
                    // Delete the file after successful read
                    try {
                        fs.unlinkSync(fullPath);
                    } catch (deleteErr) {
                        // If deletion fails, still return the content we read
                    }
                    return content.toString();
                } else {
                    // Normal GET operation: read file content without deletion
                    // Update file modification time after successful read
                    touchFile(fullPath);
                    return content.toString();
                }
            } catch (err) {
                // File doesn't exist - return empty string
                return '';
            }

        case 'DELETE':
            try {
                // Check if file exists and read content to check for channels
                const content = fs.readFileSync(fullPath);
                const contentStr = content.toString();
                
                // Check if file is a write channel before deletion
                if (contentStr.startsWith('Write channel /')) {
                    return '';
                }
                // Prevent deletion of append channels
                if (contentStr.startsWith('Append channel /')) {
                    return '';
                }
                // Prevent deletion of read channels
                if (contentStr.startsWith('Read channel /')) {
                    return '';
                }

                // Normal file - proceed with deletion
                fs.unlinkSync(fullPath);
                return formatResponsePath(path, queryStrings);
            } catch (err) {
                // File doesn't exist - return empty string
                return '';
            }

        default:
            return '';
    }
}

// JetStream nonvolatile function
function jetstream_nonvolatile(path, queryStrings, method, httpParams, inputBuffer) {
    switch (method) {
        case 'PUT':
        case 'POST':
            // Calculate hash of input buffer
            const contentHash = calculateSHA256(inputBuffer);
            const expectedPath = `/${contentHash}.dat`;
            
            // If path is NULL, empty, or /, use content hash as path
            if (!path || path === '' || path === '/') {
                return jetstream_volatile(expectedPath, queryStrings, method, httpParams, inputBuffer);
            }
            
            // If path matches content hash, store with this path
            if (path === expectedPath) {
                return jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer);
            }
            
            // Otherwise, read existing file and check hash
            const fullPath = pathModule.join(DATA_DIR, path.substring(1));
            try {
                const existingContent = fs.readFileSync(fullPath);
                const existingHash = calculateSHA256(existingContent);
                const existingExpectedPath = `/${existingHash}.dat`;
                
                // If existing content hash matches the path, ignore the PUT (content already stored)
                if (path === existingExpectedPath) {
                    return formatResponsePath(path, queryStrings);
                }
            } catch (err) {
                // File doesn't exist, continue with storage
            }
            
            // Store as key-value pair
            return jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer);
            
        case 'GET':
        case 'HEAD':
            // Forward GET and HEAD requests directly
            return jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer);
            
        case 'DELETE':
            // For DELETE, check if file exists and hash matches path (matching main.c)
            if (!path || path.length !== 69 || !path.startsWith('/') || !path.endsWith('.dat')) {
                return jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer);
            }
            
            const deleteFullPath = pathModule.join(DATA_DIR, path.substring(1));
            try {
                const existingContent = fs.readFileSync(deleteFullPath);
                const existingHash = calculateSHA256(existingContent);
                const existingExpectedPath = `/${existingHash}.dat`;
                
                // If existing content hash matches the path, ignore the DELETE
                if (path === existingExpectedPath) {
                    return '';
                }
            } catch (err) {
                // File doesn't exist, continue with deletion
            }
            
            // Hash doesn't match or file doesn't exist, proceed with delete
            return jetstream_volatile(path, queryStrings, method, httpParams, inputBuffer);
            
        default:
            return '';
    }
}

// JetStream local function
function jetstream_local(path, queryStrings, method, httpParams, inputBuffer) {
    // Pass transparently to jetstream_nonvolatile (matching main.c)
    return jetstream_nonvolatile(path, queryStrings, method, httpParams, inputBuffer);
}

// JetStream restore function
function jetstream_restore(path, queryStrings, method, httpParams, inputBuffer) {
    // For GET requests to /sha256.dat files, try to fetch from backup IPs if file is missing
    if (method === 'GET' && path.startsWith('/') && path.endsWith('.dat')) {
        // First check if file exists locally
        const fullPath = pathModule.join(DATA_DIR, pathModule.basename(path));
        if (fs.existsSync(fullPath)) {
            // File exists locally, use jetstream_local
            return jetstream_local(path, queryStrings, method, httpParams, inputBuffer);
        }
        
        // File doesn't exist locally, try to restore from backup if within timeout
        if (Date.now() - startupTime < WATCHDOG_TIMEOUT) {
            // Try each backup IP randomly
            const indices = BACKUP_IPS.map((_, i) => i).sort(() => Math.random() - 0.5);
            
            for (const idx of indices) {
                const backupIP = BACKUP_IPS[idx];
                let urlStr = backupIP;
                if (backupIP.includes('@')) {
                    urlStr = backupIP.split('@')[0];
                }
                urlStr += path;
                
                try {
                    // Temporarily disable backup restore to prevent hanging
                    // This can be re-enabled with proper async implementation later
                    console.log(`Skipping backup restore for ${path} - would try ${urlStr}`);
                    continue;
                } catch (err) {
                    // Continue to next backup IP
                    continue;
                }
            }
        }
    }
    
    // Pass through to jetstream_local for normal operation or if restore failed
    return jetstream_local(path, queryStrings, method, httpParams, inputBuffer);
}

// JetStream remote function
function jetstream_remote(path, queryStrings, method, httpParams, inputBuffer) {
    // Pass through to jetstream_restore
    return jetstream_restore(path, queryStrings, method, httpParams, inputBuffer);
}

// JetStream application function
// JetStream application function
function jetstream_application(path, queryStrings, method, httpParams, inputBuffer) {
    // Check for burst parameter
    if (queryStrings.includes('burst=1')) {
        if (method === 'GET') {
            // Burst GET: call jetstream_remote to get list of chunk hashes
            const listResult = jetstream_remote(path, queryStrings, method, httpParams, inputBuffer);
            if (!listResult) {
                return '';
            }
            
            // Parse newline-separated list of /sha256.dat values
            const hashList = listResult.split('\n').filter(hash => hash.trim());
            const contentChunks = [];
            
            // Limit number of hash entries to prevent memory exhaustion
            const maxHashes = Math.min(hashList.length, 1000);
            
            if (maxHashes === 0) {
                return '';
            }
            
            // Process each hash synchronously
            for (let i = 0; i < maxHashes; i++) {
                const hashPath = hashList[i].trim();
                if (hashPath.startsWith('/') && hashPath.endsWith('.dat') && hashPath.length === 69) {
                    const chunkContent = jetstream_remote(hashPath, [], 'GET', [], Buffer.alloc(0));
                    if (chunkContent) {
                        contentChunks.push(chunkContent);
                    }
                }
            }
            
            // Join all chunks
            return contentChunks.join('');
        }
        
        if (method === 'PUT' || method === 'POST') {
            // Burst PUT/POST: split input into 4KB chunks and store each
            const sha256List = [];
            const CHUNK_SIZE = 4096;
            
            // Process input in 4096-byte blocks
            for (let offset = 0; offset < inputBuffer.length; offset += CHUNK_SIZE) {
                const blockSize = Math.min(CHUNK_SIZE, inputBuffer.length - offset);
                const block = inputBuffer.slice(offset, offset + blockSize);
                
                // Store this block via jetstream_remote (use null path like main.c)
                const blockResponse = jetstream_remote(null, [], method, httpParams, block);
                
                // Add SHA256 path to list if valid
                if (blockResponse && blockResponse.length > 0) {
                    sha256List.push(blockResponse);
                }
            }
            
            // All blocks processed, store the collected SHA256 list
            const hashList = sha256List.join('\n');
            const hashListBuffer = Buffer.from(hashList);
            return jetstream_remote(path, queryStrings.filter(q => q !== 'burst=1'), method, httpParams, hashListBuffer);
        }
    }
    
    // Pass transparently to jetstream_remote for non-burst requests
    let response = jetstream_remote(path, queryStrings, method, httpParams, inputBuffer);
    
    // For GET operations, check if the result is empty and attempt restore if within timeout
    if (method === 'GET' && (!response || response.length === 0) && Date.now() - startupTime < WATCHDOG_TIMEOUT) {
        // Attempt restore for failed GET
        const restoreResult = jetstream_restore(path, queryStrings, method, httpParams, inputBuffer);
        if (restoreResult && restoreResult.length > 0) {
            response = restoreResult;
        }
    }
    
    // Check if the response is a write channel for PUT/POST operations
    if ((method === 'PUT' || method === 'POST') && response && response.length > 15) {
        if (response.startsWith('Write channel /')) {
            // Extract the target path from "Write channel /sha256.dat"
            const targetPath = response.substring(14); // Skip "Write channel "
            const endMarker = targetPath.indexOf('.dat');
            if (endMarker !== -1 && targetPath.length >= 69) {
                // Validate target path format
                if (targetPath.startsWith('/') && targetPath.substring(endMarker) === '.dat') {
                    // Check if target file exists for append operations before redirecting
                    if (queryStrings.some(q => q.includes('append=1'))) {
                        const fullPath = pathModule.join(DATA_DIR, pathModule.basename(targetPath));
                        if (!fs.existsSync(fullPath) && Date.now() - startupTime < WATCHDOG_TIMEOUT) {
                            // Target file doesn't exist, try restore first
                            jetstream_restore(targetPath, [], 'GET', [], Buffer.alloc(0));
                        }
                    }
                    
                    // Call jetstream_remote with the redirected path
                    jetstream_remote(targetPath, queryStrings, method, httpParams, inputBuffer);
                    // Return the channel path to hide the target
                    return formatResponsePath(path, queryStrings);
                }
            }
        }
    }
    
    // Check if the response is an append channel for PUT/POST operations
    if ((method === 'PUT' || method === 'POST') && response && response.length > 16) {
        if (response.startsWith('Append channel /')) {
            // Extract the target path from "Append channel /sha256.dat"
            const targetPath = response.substring(15); // Skip "Append channel "
            const endMarker = targetPath.indexOf('.dat');
            if (endMarker !== -1 && targetPath.length >= 69) {
                // Validate target path format
                if (targetPath.startsWith('/') && targetPath.substring(endMarker) === '.dat') {
                    // Check if target file exists before appending
                    const fullPath = pathModule.join(DATA_DIR, pathModule.basename(targetPath));
                    if (!fs.existsSync(fullPath) && Date.now() - startupTime < WATCHDOG_TIMEOUT) {
                        // Target file doesn't exist, try restore first
                        jetstream_restore(targetPath, [], 'GET', [], Buffer.alloc(0));
                    }
                    
                    // Add append=1 to query strings
                    const appendQueryStrings = [...queryStrings, 'append=1'];
                    
                    // Call jetstream_remote with the redirected path and append=1
                    jetstream_remote(targetPath, appendQueryStrings, method, httpParams, inputBuffer);
                    // Return the channel path to hide the target
                    return formatResponsePath(path, queryStrings);
                }
            }
        }
    }
    
    // Check if the response is a read channel for GET operations
    if (method === 'GET' && response && response.length > 14) {
        if (response.startsWith('Read channel /')) {
            // Extract the target path from "Read channel /sha256.dat"
            const targetPath = response.substring(13); // Skip "Read channel "
            const endMarker = targetPath.indexOf('.dat');
            if (endMarker !== -1 && targetPath.length >= 69) {
                // Validate target path format
                if (targetPath.startsWith('/') && targetPath.substring(endMarker) === '.dat') {
                    // Call jetstream_remote with the redirected path to get target file content
                    let channelResult = jetstream_remote(targetPath, queryStrings, method, httpParams, inputBuffer);
                    
                    // If read channel target failed and we got empty result, try restore
                    if ((!channelResult || channelResult.length === 0) && Date.now() - startupTime < WATCHDOG_TIMEOUT) {
                        const restoreResult = jetstream_restore(targetPath, queryStrings, method, httpParams, inputBuffer);
                        if (restoreResult) {
                            channelResult = restoreResult;
                        }
                    }
                    return channelResult;
                }
            }
        }
    }
    
    // Return the original response
    return response;
}

// HTTP request handler
function httpHandler(req, res) {
    let body = Buffer.alloc(0);
    let requestAborted = false;
    
    req.on('data', (chunk) => {
        // Prevent processing if request already aborted
        if (requestAborted) {
            return;
        }
        
        // Only enforce MAX_FILE_SIZE for uploads
        if (body.length + chunk.length > MAX_FILE_SIZE) {
            requestAborted = true;
            req.destroy(); // Immediately close the connection
            if (!res.headersSent) {
                res.writeHead(413, { 'Content-Type': 'text/plain' });
                res.end('Request entity too large');
            }
            return;
        }
        
        // Optimize buffer concatenation to reduce memory spikes
        const newBody = Buffer.allocUnsafe(body.length + chunk.length);
        body.copy(newBody, 0);
        chunk.copy(newBody, body.length);
        body = newBody;
    });
    
    req.on('end', () => {
        // Prevent processing if request was aborted
        if (requestAborted) {
            return;
        }
        
        try {
            const parsedUrl = url.parse(req.url, true);
            const path = parsedUrl.pathname || '/';
            const queryStrings = [];
            
            // Convert query parameters to array format
            for (const [key, value] of Object.entries(parsedUrl.query || {})) {
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
            for (const [key, value] of Object.entries(req.headers || {})) {
                httpParams.push(`${key}: ${value}`);
            }
            
            // Call jetstream_application with error handling
            let result = jetstream_application(path, queryStrings, method, httpParams, body);
            if (result === null || result === undefined) {
                result = '';
            }
            
            // Check if response headers already sent before writing
            if (!res.headersSent) {
                res.writeHead(200, {
                    'Content-Type': 'text/plain',
                    'Content-Length': Buffer.byteLength(result),
                    'Connection': 'close'
                });
                res.end(result);
            }
        } catch (error) {
            // Handle any errors gracefully
            console.error('Request processing error:', error.message);
            if (!res.headersSent) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal server error');
            }
        }
    });
    
    req.on('error', (err) => {
        console.error('Request error:', err.message);
        requestAborted = true;
        if (!res.headersSent) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('Bad request');
        }
    });
    
    // Add timeout handling for requests
    req.on('timeout', () => {
        console.error('Request timeout');
        requestAborted = true;
        req.destroy();
        if (!res.headersSent) {
            res.writeHead(408, { 'Content-Type': 'text/plain' });
            res.end('Request timeout');
        }
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
                } else {
                    // Not deleted, backup
                    if (file.endsWith('.dat') && file.length === 68) {
                        const sha256Name = file;
                        jetstream_backup(filePath, sha256Name);
                    }
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
        
        // Add connection limiting and proper timeout handling
        let activeConnections = 0;
        const MAX_CONNECTIONS = 100;
        
        httpsServer.on('connection', (socket) => {
            activeConnections++;
            
            // Reject connections if over limit
            if (activeConnections > MAX_CONNECTIONS) {
                socket.destroy();
                activeConnections--;
                return;
            }
            
            socket.setTimeout(10000); // 10 second socket timeout
            
            socket.on('close', () => {
                activeConnections--;
            });
            
            socket.on('error', (err) => {
                console.error('Socket error:', err.message);
                activeConnections--;
            });
        });
        
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
    
    // Add connection limiting and proper timeout handling
    let activeConnections = 0;
    const MAX_CONNECTIONS = 100;
    
    httpServer.on('connection', (socket) => {
        activeConnections++;
        
        // Reject connections if over limit
        if (activeConnections > MAX_CONNECTIONS) {
            socket.destroy();
            activeConnections--;
            return;
        }
        
        socket.setTimeout(10000); // 10 second socket timeout
        
        socket.on('close', () => {
            activeConnections--;
        });
        
        socket.on('error', (err) => {
            console.error('Socket error:', err.message);
            activeConnections--;
        });
    });
    
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