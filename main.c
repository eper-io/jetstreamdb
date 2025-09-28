#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <utime.h>

/*
gcc -o main main.c -lpthread -lssl -lcrypto -lcurl -ljansson -Wl,-z,noexecstack && ./main
cat main.c | grep gcc | head -n 1 | bash
*/

#define MAX_FILE_SIZE (1024 * 1024)  // 1 megabyte file size limit
#define WATCHDOG_TIMEOUT 60          // 60 seconds watchdog timeout
#define DATA "/data"                 // Data directory
#define MAX_REQUEST_SIZE 8192        // Maximum HTTP request size
#define MAX_RESPONSE_SIZE (2 * 1024 * 1024)  // Maximum response size
#define MAX_CONCURRENT_CONNECTIONS 100  // Maximum concurrent connections

// Global startup time
static time_t startup_time;

// Connection limiting
static int active_connections = 0;
static pthread_mutex_t connection_mutex = PTHREAD_MUTEX_INITIALIZER;

// Node configuration (2D array of nodes)
// Global backup IP array
static const char* BACKUP_IPS[] = {
    "http://18.209.57.108@hour.schmied.us"
};
static const int NUM_BACKUP_IPS = sizeof(BACKUP_IPS) / sizeof(BACKUP_IPS[0]);

// Helper: choose random backup IP
const char* get_random_backup_ip() {
    srand((unsigned int)time(NULL) ^ getpid());
    int idx = rand() % NUM_BACKUP_IPS;
    return BACKUP_IPS[idx];
}

// Helper: extract domain name from https://ip@name
const char* extract_domain(const char* url) {
    const char* at = strchr(url, '@');
    return at ? at + 1 : NULL;
}

#include <curl/curl.h>

// Structure for cURL response data
struct curl_response {
    char* data;
    size_t size;
};

// Backup function: PUT file to backup IP at /sha256.dat
void jetstream_backup(const char* file_path, const char* sha256_name) {
    const char* backup_ip = get_random_backup_ip();
    char url[512];
    if (strchr(backup_ip, '@')) {
        char ip_part[256];
        strncpy(ip_part, backup_ip, strchr(backup_ip, '@') - backup_ip);
        ip_part[strchr(backup_ip, '@') - backup_ip] = '\0';
        snprintf(url, sizeof(url), "%s/%s", ip_part, sha256_name);
    } else {
        snprintf(url, sizeof(url), "%s/%s", backup_ip, sha256_name);
    }

    FILE* f = fopen(file_path, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* buf = malloc(size);
    if (!buf) { fclose(f); return; }
    fread(buf, 1, size, f);
    fclose(f);

    CURL* curl = curl_easy_init();
    if (!curl) { free(buf); return; }
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, size);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    // TLS verification if needed
    if (strstr(backup_ip, "https://") && strchr(backup_ip, '@')) {
        const char* domain = extract_domain(backup_ip);
        if (domain) curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        if (domain) curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        if (domain) curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
    }
    curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(buf);
}

// Global backup IP array

// Structure for client connection data
typedef struct {
    int socket;
    SSL* ssl;
    struct sockaddr_in address;
} client_connection_t;

// HTTP request structure
typedef struct {
    char method[16];
    char path[256];
    char** query_strings;
    char** http_params;
    char* body;
    size_t body_length;
} http_request_t;

// Function declarations
void jetstream_server(void);
void* handle_client(void* arg);
int parse_http_request(const char* request, http_request_t* parsed);
void free_http_request(http_request_t* req);
char* sha256_hex(const void* data, size_t len);

// Jetstream function declarations
void jetstream_volatile(const char* path, const char** query_strings, const char* method, 
                       const char** http_params, const void* input_buffer, size_t input_size,
                       void* output_buffer, size_t output_size);

void jetstream_nonvolatile(const char* path, const char** query_strings, const char* method,
                           const char** http_params, const void* input_buffer, size_t input_size,
                           void* output_buffer, size_t output_size);

void jetstream_local(const char* path, const char** query_strings, const char* method,
                     const char** http_params, const void* input_buffer, size_t input_size,
                     void* output_buffer, size_t output_size);

void jetstream_restore(const char* path, const char** query_strings, const char* method,
                       const char** http_params, const void* input_buffer, size_t input_size,
                       void* output_buffer, size_t output_size);

void jetstream_remote(const char* path, const char** query_strings, const char* method,
                      const char** http_params, const void* input_buffer, size_t input_size,
                      void* output_buffer, size_t output_size);

void jetstream_application(const char* path, const char** query_strings, const char* method,
                           const char** http_params, const void* input_buffer, size_t input_size,
                           void* output_buffer, size_t output_size);

// Helper function to calculate SHA256 hash
char* sha256_hex(const void* data, size_t len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char* hex_string = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    
    if (!hex_string) {
        return NULL;
    }
    
    SHA256(data, len, hash);
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(hex_string + (i * 2), 3, "%02x", hash[i]);
    }
    hex_string[SHA256_DIGEST_LENGTH * 2] = '\0';
    
    return hex_string;
}

// Parse HTTP request
int parse_http_request(const char* request, http_request_t* parsed) {
    if (!request || !parsed) {
        return -1;
    }
    
    char* request_copy = strdup(request);
    if (!request_copy) {
        return -1;
    }
    
    char* line = strtok(request_copy, "\r\n");
    
    if (!line) {
        free(request_copy);
        return -1;
    }
    
    // Parse request line (METHOD PATH HTTP/1.1)
    char* method = strtok(line, " ");
    char* path = strtok(NULL, " ");
    
    if (!method || !path) {
        free(request_copy);
        return -1;
    }
    
    strncpy(parsed->method, method, sizeof(parsed->method) - 1);
    parsed->method[sizeof(parsed->method) - 1] = '\0';
    
    // Parse path and query string
    char* query_start = strchr(path, '?');
    if (query_start) {
        *query_start = '\0';
        query_start++;
        
        // Count query parameters
        int param_count = 1;
        char* temp = query_start;
        while ((temp = strchr(temp, '&')) != NULL) {
            param_count++;
            temp++;
        }
        
        // Allocate array for query strings
        parsed->query_strings = malloc((param_count + 1) * sizeof(char*));
        if (!parsed->query_strings) {
            free(request_copy);
            return -1;
        }
        
        // Parse query parameters
        char* query_copy = strdup(query_start);
        if (!query_copy) {
            free(parsed->query_strings);
            free(request_copy);
            return -1;
        }
        
        char* param = strtok(query_copy, "&");
        int i = 0;
        while (param && i < param_count) {
            parsed->query_strings[i] = strdup(param);
            if (!parsed->query_strings[i]) {
                // Free previously allocated strings on failure
                for (int j = 0; j < i; j++) {
                    free(parsed->query_strings[j]);
                }
                free(parsed->query_strings);
                free(query_copy);
                free(request_copy);
                return -1;
            }
            param = strtok(NULL, "&");
            i++;
        }
        parsed->query_strings[i] = NULL;
        free(query_copy);
    } else {
        parsed->query_strings = NULL;
    }
    
    strncpy(parsed->path, path, sizeof(parsed->path) - 1);
    parsed->path[sizeof(parsed->path) - 1] = '\0';
    parsed->http_params = NULL;
    
    // Find body (after empty line)
    char* body_start = strstr(request, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        parsed->body_length = strlen(body_start);
        if (parsed->body_length > MAX_FILE_SIZE) {
            parsed->body_length = MAX_FILE_SIZE;
        }
        parsed->body = malloc(parsed->body_length + 1);
        if (parsed->body) {
            memcpy(parsed->body, body_start, parsed->body_length);
            parsed->body[parsed->body_length] = '\0';
        }
    } else {
        parsed->body = NULL;
        parsed->body_length = 0;
    }
    
    free(request_copy);
    return 0;
}

// Free HTTP request structure
void free_http_request(http_request_t* req) {
    if (req->body) free(req->body);
    if (req->query_strings) {
        for (int i = 0; req->query_strings[i]; i++) {
            free(req->query_strings[i]);
        }
        free(req->query_strings);
    }
    if (req->http_params) {
        for (int i = 0; req->http_params[i]; i++) {
            free(req->http_params[i]);
        }
        free(req->http_params);
    }
}

// Handle client connection
void* handle_client(void* arg) {
    client_connection_t* client = (client_connection_t*)arg;
    // Set socket receive timeout (10 seconds)
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(client->socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    char buffer[MAX_REQUEST_SIZE];
    char response[MAX_RESPONSE_SIZE];
    int bytes_read;
    
    // Read HTTP request
    if (client->ssl) {
        bytes_read = SSL_read(client->ssl, buffer, sizeof(buffer) - 1);
    } else {
        bytes_read = recv(client->socket, buffer, sizeof(buffer) - 1, 0);
    }
    
    if (bytes_read <= 0) {
        goto cleanup;
    }
    
    buffer[bytes_read] = '\0';
    
    // Parse HTTP request
    http_request_t request;
    memset(&request, 0, sizeof(request));
    
    if (parse_http_request(buffer, &request) != 0) {
        const char* error_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        if (client->ssl) {
            SSL_write(client->ssl, error_response, strlen(error_response));
        } else {
            send(client->socket, error_response, strlen(error_response), 0);
        }
        free_http_request(&request);
        goto cleanup;
    }
    
    // Prepare output buffer for jetstream_application
    char output_buffer[MAX_RESPONSE_SIZE];
    memset(output_buffer, 0, sizeof(output_buffer));
    
    // Call jetstream_application
    jetstream_application(request.path, (const char**)request.query_strings, request.method,
                         (const char**)request.http_params, request.body, request.body_length,
                         output_buffer, sizeof(output_buffer));
    
    // Create HTTP response
    int content_length = strlen(output_buffer);
    snprintf(response, sizeof(response),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: text/plain\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n"
             "\r\n%s", content_length, output_buffer);
    
    // Send response
    if (client->ssl) {
        SSL_write(client->ssl, response, strlen(response));
    } else {
        send(client->socket, response, strlen(response), 0);
    }
    
    free_http_request(&request);
    
cleanup:
    // Decrement active connection counter
    pthread_mutex_lock(&connection_mutex);
    active_connections--;
    pthread_mutex_unlock(&connection_mutex);
    
    if (client->ssl) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
    }
    close(client->socket);
    free(client);
    return NULL;
}

// Main server function
void jetstream_server(void) {
    int server_socket;
    struct sockaddr_in server_addr;
    SSL_CTX* ssl_ctx = NULL;
    int use_tls = 0;
    int port;

    // Ensure /data directory exists
    if (mkdir(DATA, 0755) < 0 && errno != EEXIST) {
        perror("Failed to create /data directory");
        return;
    }
    
    // Check for TLS certificates (match main.go logic)
    if (access("/etc/ssl/jetstream.key", F_OK) == 0) {
        use_tls = 1;
        port = 443;
        
        // Initialize OpenSSL
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        
        ssl_ctx = SSL_CTX_new(TLS_server_method());
        if (!ssl_ctx) {
            fprintf(stderr, "Failed to create SSL context\n");
            return;
        }
        
        // Set SSL options for better compatibility
        SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
        
        // Load certificate chain (this handles intermediate certificates)
        if (SSL_CTX_use_certificate_chain_file(ssl_ctx, "/etc/ssl/jetstream.crt") <= 0) {
            fprintf(stderr, "Failed to load SSL certificate chain\n");
            SSL_CTX_free(ssl_ctx);
            return;
        }
        
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "/etc/ssl/jetstream.key", SSL_FILETYPE_PEM) <= 0) {
            fprintf(stderr, "Failed to load SSL private key\n");
            SSL_CTX_free(ssl_ctx);
            return;
        }
        
        // Verify that the private key matches the certificate
        if (!SSL_CTX_check_private_key(ssl_ctx)) {
            fprintf(stderr, "Private key does not match certificate\n");
            SSL_CTX_free(ssl_ctx);
            return;
        }
    } else {
        port = 7777;
    }
    
    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
        return;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind socket
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
        return;
    }
    
    // Listen for connections
    if (listen(server_socket, 10) < 0) {
        perror("Listen failed");
        close(server_socket);
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
        return;
    }
    
    printf("Jetstream server listening on port %d (%s)\n", port, use_tls ? "HTTPS" : "HTTP");
    
    // Accept connections
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }
        
        // Check connection limit
        pthread_mutex_lock(&connection_mutex);
        if (active_connections >= MAX_CONCURRENT_CONNECTIONS) {
            pthread_mutex_unlock(&connection_mutex);
            close(client_socket);
            continue;
        }
        active_connections++;
        pthread_mutex_unlock(&connection_mutex);
        
        // Create client connection structure
        client_connection_t* client = malloc(sizeof(client_connection_t));
        if (!client) {
            // Decrement counter on malloc failure
            pthread_mutex_lock(&connection_mutex);
            active_connections--;
            pthread_mutex_unlock(&connection_mutex);
            close(client_socket);
            continue;
        }
        client->socket = client_socket;
        client->address = client_addr;
        client->ssl = NULL;
        
        if (use_tls) {
            client->ssl = SSL_new(ssl_ctx);
            SSL_set_fd(client->ssl, client_socket);
            if (SSL_accept(client->ssl) <= 0) {
                SSL_free(client->ssl);
                close(client_socket);
                free(client);
                // Decrement counter on SSL failure
                pthread_mutex_lock(&connection_mutex);
                active_connections--;
                pthread_mutex_unlock(&connection_mutex);
                continue;
            }
        }
        
        // Handle client in separate thread
        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, client);
        pthread_detach(thread);
    }
    
    close(server_socket);
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
}

// Jetstream function implementations (empty for now)
// Function declarations
const char* find_format_parameter(const char** query_strings);
int find_append_parameter(const char** query_strings);

// Helper function to find take parameter in query strings
int find_take_parameter(const char** query_strings) {
    if (!query_strings) return 0;
    
    for (int i = 0; query_strings[i]; i++) {
        if (strncmp(query_strings[i], "take=1", 6) == 0) {
            return 1;
        }
    }
    return 0;
}

// Watchdog thread function to clean up old files
void* watchdog_thread(void* arg) {
    (void)arg; // Suppress unused parameter warning
    
    while (1) {
        sleep(WATCHDOG_TIMEOUT);
        
        DIR* dir = opendir(DATA);
        if (!dir) {
            continue; // Skip if can't open directory
        }
        
        struct dirent* entry;
        time_t current_time = time(NULL);
        
        while ((entry = readdir(dir)) != NULL) {
            // Skip . and .. entries
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            
            // Only process .dat files
            size_t name_len = strlen(entry->d_name);
            if (name_len < 4 || strcmp(entry->d_name + name_len - 4, ".dat") != 0) {
                continue;
            }
            
            // Build full file path
            char filepath[512];
            int ret = snprintf(filepath, sizeof(filepath), "%s/%s", DATA, entry->d_name);
            if (ret >= (int)sizeof(filepath)) {
                continue; // Skip if path too long
            }
            
            // Get file modification time
            struct stat file_stat;
            if (stat(filepath, &file_stat) == 0) {
                // Check if file is older than WATCHDOG_TIMEOUT seconds
                if (current_time - file_stat.st_mtime > WATCHDOG_TIMEOUT) {
                    unlink(filepath); // Delete the file
                } else {
                    // Not deleted, backup
                    jetstream_backup(filepath, entry->d_name);
                }
            }
        }
        
        closedir(dir);
    }
    
    return NULL;
}

// Helper function to find format parameter in query strings
const char* find_format_parameter(const char** query_strings) {
    if (!query_strings) return NULL;
    
    for (int i = 0; query_strings[i]; i++) {
        if (strncmp(query_strings[i], "format=", 7) == 0) {
            return query_strings[i] + 7; // Return value after "format="
        }
    }
    return NULL;
}

// Helper function to replace placeholders in format string
void format_response_path(const char* format_template, const char* path, char* output_buffer, size_t output_size) {
    if (!format_template) {
        strncpy(output_buffer, path, output_size - 1);
        output_buffer[output_size - 1] = '\0';
        return;
    }
    
    char temp_buffer[2048];
    const char* src = format_template;
    char* dst = temp_buffer;
    size_t remaining = sizeof(temp_buffer) - 1;
    
    while (*src && remaining > 0) {
        if (strncmp(src, "%25s", 4) == 0) {
            // Replace %25s (URL-encoded %s) with path
            size_t path_len = strlen(path);
            if (path_len <= remaining) {
                strcpy(dst, path);
                dst += path_len;
                remaining -= path_len;
            }
            src += 4;
        } else if (strncmp(src, "%s", 2) == 0) {
            // Replace %s with path
            size_t path_len = strlen(path);
            if (path_len <= remaining) {
                strcpy(dst, path);
                dst += path_len;
                remaining -= path_len;
            }
            src += 2;
        } else if (*src == '*') {
            // Replace * with path
            size_t path_len = strlen(path);
            if (path_len <= remaining) {
                strcpy(dst, path);
                dst += path_len;
                remaining -= path_len;
            }
            src++;
        } else {
            // Copy character as-is
            *dst++ = *src++;
            remaining--;
        }
    }
    *dst = '\0';
    
    strncpy(output_buffer, temp_buffer, output_size - 1);
    output_buffer[output_size - 1] = '\0';
}

void jetstream_volatile(const char* path, const char** query_strings, const char* method, 
                       const char** http_params, const void* input_buffer, size_t input_size,
                       void* output_buffer, size_t output_size) {
    char filepath[512];
    
    // Validate inputs
    if (!path || !method || !output_buffer || output_size == 0) {
        if (output_buffer && output_size > 0) {
            ((char*)output_buffer)[0] = '\0';
        }
        return;
    }
    
    // Validate path format: must be /sha256.dat where sha256 is 64 hex characters
    if (strlen(path) != 69 || path[0] != '/' || strcmp(path + 65, ".dat") != 0) {
        ((char*)output_buffer)[0] = '\0';
        return;
    }
    
    // Validate that the middle part is 64 hex characters
    for (int i = 1; i <= 64; i++) {
        char c = path[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            ((char*)output_buffer)[0] = '\0';
            return;
        }
    }
    
    // Find format parameter for response formatting
    const char* format_template = find_format_parameter(query_strings);
    
    if (strcmp(method, "PUT") == 0 || strcmp(method, "POST") == 0) {
        // Check for append mode
        int append_mode = find_append_parameter(query_strings);
        
        int ret = snprintf(filepath, sizeof(filepath), "%s%s", DATA, path);
        if (ret >= (int)sizeof(filepath)) {
            ((char*)output_buffer)[0] = '\0';
            return;
        }
        
        // Check for channel write: read existing file content first
        char existing_content[512];
        existing_content[0] = '\0';
        int is_creating_channel = 0;
        int existing_fd = open(filepath, O_RDONLY);
        if (existing_fd >= 0) {
            ssize_t bytes_read = read(existing_fd, existing_content, sizeof(existing_content) - 1);
            close(existing_fd);
            if (bytes_read > 0) {
                existing_content[bytes_read] = '\0';
                // Check if existing content is a write channel
                if (strncmp(existing_content, "Write channel /", 15) == 0) {
                    // Check if we're trying to create the same channel content
                    if (input_buffer && input_size > 15 && 
                        strncmp((char*)input_buffer, "Write channel /", 15) == 0 &&
                        strncmp((char*)input_buffer, existing_content, input_size) == 0) {
                        // Creating the same channel, return channel path
                        format_response_path(format_template, path, (char*)output_buffer, output_size);
                        return;
                    } else {
                        // Writing to existing channel, return channel content for redirection
                        strncpy((char*)output_buffer, existing_content, output_size - 1);
                        ((char*)output_buffer)[output_size - 1] = '\0';
                        return;
                    }
                }
                // Check if existing content is an append channel
                if (strncmp(existing_content, "Append channel /", 16) == 0) {
                    // Check if we're trying to create the same channel content
                    if (input_buffer && input_size > 16 && 
                        strncmp((char*)input_buffer, "Append channel /", 16) == 0 &&
                        strncmp((char*)input_buffer, existing_content, input_size) == 0) {
                        // Creating the same channel, return channel path
                        format_response_path(format_template, path, (char*)output_buffer, output_size);
                        return;
                    } else {
                        // Writing to existing channel, return channel content for redirection
                        strncpy((char*)output_buffer, existing_content, output_size - 1);
                        ((char*)output_buffer)[output_size - 1] = '\0';
                        return;
                    }
                }
                // Check if existing content is a read channel
                if (strncmp(existing_content, "Read channel /", 14) == 0) {
                    // Read channels cannot be written to, return empty string
                    ((char*)output_buffer)[0] = '\0';
                    return;
                }
            }
        }
        
        int fd;
        if (append_mode) {
            // Open with append mode, create if doesn't exist
            fd = open(filepath, O_CREAT | O_WRONLY | O_APPEND, 0644);
        } else {
            // Create or truncate file and save content
            fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        }
        
        if (fd >= 0) {
            ssize_t bytes_written = 0;
            if (input_buffer && input_size > 0) {
                if (input_size > MAX_FILE_SIZE) {
                    input_size = MAX_FILE_SIZE;
                }
                bytes_written = write(fd, input_buffer, input_size);
            }
            close(fd);
            
            if (bytes_written == (ssize_t)input_size) {
                // Update file modification time to prevent watchdog deletion
                utime(filepath, NULL);
                
                // Check if we just created a write channel
                if (input_buffer && input_size > 15 && strncmp((char*)input_buffer, "Write channel /", 15) == 0) {
                    // For write channel creation, return the channel path (not the content)
                    format_response_path(format_template, path, (char*)output_buffer, output_size);
                } else {
                    // For normal file creation, return the path
                    format_response_path(format_template, path, (char*)output_buffer, output_size);
                }
            } else {
                ((char*)output_buffer)[0] = '\0';
            }
        } else {
            ((char*)output_buffer)[0] = '\0';
        }
        
    } else if (strcmp(method, "GET") == 0) {
        // Check for take mode
        int take_mode = find_take_parameter(query_strings);
        
        int ret = snprintf(filepath, sizeof(filepath), "%s%s", DATA, path);
        if (ret >= (int)sizeof(filepath)) {
            ((char*)output_buffer)[0] = '\0';
            return;
        }
        
        if (take_mode) {
            // Take operation: read content then delete file atomically
            int fd = open(filepath, O_RDONLY);
            if (fd >= 0) {
                ssize_t bytes_read = read(fd, output_buffer, output_size - 1);
                close(fd);
                
                if (bytes_read >= 0) {
                    ((char*)output_buffer)[bytes_read] = '\0';
                    // Check if content is a write channel, return empty string if so
                    if (strncmp((char*)output_buffer, "Write channel /", 15) == 0) {
                        ((char*)output_buffer)[0] = '\0';
                        return;
                    }
                    // Check if content is a read channel, return channel content for redirection
                    if (strncmp((char*)output_buffer, "Read channel /", 14) == 0) {
                        // For read channels, return the channel content for redirection
                        // Don't delete the file in take mode for read channels
                        return;
                    }
                    // Update file modification time before deletion
                    utime(filepath, NULL);
                    // Delete the file after successful read
                    unlink(filepath);
                } else {
                    ((char*)output_buffer)[0] = '\0';
                }
            } else {
                // File doesn't exist, return empty string
                ((char*)output_buffer)[0] = '\0';
            }
        } else {
            // Normal GET operation: read file content without deletion
            int fd = open(filepath, O_RDONLY);
            if (fd >= 0) {
                ssize_t bytes_read = read(fd, output_buffer, output_size - 1);
                close(fd);
                
                if (bytes_read >= 0) {
                    ((char*)output_buffer)[bytes_read] = '\0';
                    // Check if content is a write channel, return empty string if so
                    if (strncmp((char*)output_buffer, "Write channel /", 15) == 0) {
                        ((char*)output_buffer)[0] = '\0';
                        return;
                    }
                    // Check if content is an append channel, return empty string if so
                    if (strncmp((char*)output_buffer, "Append channel /", 16) == 0) {
                        ((char*)output_buffer)[0] = '\0';
                        return;
                    }
                    // Check if content is a read channel, return channel content for redirection
                    if (strncmp((char*)output_buffer, "Read channel /", 14) == 0) {
                        // For read channels, return the channel content for redirection
                        return;
                    }
                    // Update file modification time after successful read
                    utime(filepath, NULL);
                } else {
                    ((char*)output_buffer)[0] = '\0';
                }
            } else {
                ((char*)output_buffer)[0] = '\0';
            }
        }
        
    } else if (strcmp(method, "DELETE") == 0) {
        // Unlink file
        int ret = snprintf(filepath, sizeof(filepath), "%s%s", DATA, path);
        if (ret >= (int)sizeof(filepath)) {
            ((char*)output_buffer)[0] = '\0';
            return;
        }
        
        // Check if file is a write channel before deletion
        char file_content[512];
        file_content[0] = '\0';
        int check_fd = open(filepath, O_RDONLY);
        if (check_fd >= 0) {
            ssize_t bytes_read = read(check_fd, file_content, sizeof(file_content) - 1);
            close(check_fd);
            if (bytes_read > 0) {
                file_content[bytes_read] = '\0';
                // Prevent deletion of write channels
                if (strncmp(file_content, "Write channel /", 15) == 0) {
                    ((char*)output_buffer)[0] = '\0';
                    return;
                }
                // Prevent deletion of append channels
                if (strncmp(file_content, "Append channel /", 16) == 0) {
                    ((char*)output_buffer)[0] = '\0';
                    return;
                }
                // Prevent deletion of read channels
                if (strncmp(file_content, "Read channel /", 14) == 0) {
                    ((char*)output_buffer)[0] = '\0';
                    return;
                }
            }
        }
        
        if (unlink(filepath) == 0) {
            // File existed and was deleted, format the response path
            format_response_path(format_template, path, (char*)output_buffer, output_size);
        } else {
            // File didn't exist or error occurred, return empty string
            ((char*)output_buffer)[0] = '\0';
        }
        
    } else {
        // Unsupported method
        ((char*)output_buffer)[0] = '\0';
    }
}

void jetstream_nonvolatile(const char* path, const char** query_strings, const char* method,
                           const char** http_params, const void* input_buffer, size_t input_size,
                           void* output_buffer, size_t output_size) {
    // Validate inputs
    if (!method || !output_buffer || output_size == 0) {
        if (output_buffer && output_size > 0) {
            ((char*)output_buffer)[0] = '\0';
        }
        return;
    }
    
    // Forward GET and HEAD requests transparently
    if (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0) {
        jetstream_volatile(path, query_strings, method, http_params, input_buffer, input_size, output_buffer, output_size);
        return;
    }
    
    if (strcmp(method, "PUT") == 0 || strcmp(method, "POST") == 0) {
        // Hash the content to be written
        char* content_hash = NULL;
        if (input_buffer && input_size > 0) {
            content_hash = sha256_hex(input_buffer, input_size);
            if (!content_hash) {
                ((char*)output_buffer)[0] = '\0';
                return;
            }
        } else {
            ((char*)output_buffer)[0] = '\0';
            return;
        }
        
        char content_path[256];
        snprintf(content_path, sizeof(content_path), "/%s.dat", content_hash);
        
        // Handle special paths (NULL, empty, or /)
        if (!path || strlen(path) == 0 || strcmp(path, "/") == 0) {
            // Use content hash as path
            jetstream_volatile(content_path, query_strings, method, http_params, input_buffer, input_size, output_buffer, output_size);
            free(content_hash);
            return;
        }
        
        // Validate path format and extract hash
        if (strlen(path) == 69 && path[0] == '/' && strcmp(path + 65, ".dat") == 0) {
            char path_hash[65];
            strncpy(path_hash, path + 1, 64);
            path_hash[64] = '\0';
            
            // Check if path hash matches content hash
            if (strcmp(path_hash, content_hash) == 0) {
                // Hash matches, call jetstream_volatile with this path
                jetstream_volatile(path, query_strings, method, http_params, input_buffer, input_size, output_buffer, output_size);
                free(content_hash);
                return;
            }
        }
        
        // Read existing file and compare hashes
        char filepath[512];
        int ret = snprintf(filepath, sizeof(filepath), "%s%s", DATA, path);
        if (ret >= (int)sizeof(filepath)) {
            ((char*)output_buffer)[0] = '\0';
            free(content_hash);
            return;
        }
        
        int fd = open(filepath, O_RDONLY);
        if (fd >= 0) {
            // File exists, read and hash it
            char file_buffer[MAX_FILE_SIZE];
            ssize_t bytes_read = read(fd, file_buffer, sizeof(file_buffer));
            close(fd);
            
            if (bytes_read > 0) {
                char* file_hash = sha256_hex(file_buffer, bytes_read);
                if (file_hash) {
                    // Compare with path hash
                    char path_hash[65];
                    strncpy(path_hash, path + 1, 64);
                    path_hash[64] = '\0';
                    
                    if (strcmp(path_hash, file_hash) == 0) {
                        // Hashes match, proceed with delete
                        jetstream_volatile(path, query_strings, method, http_params, input_buffer, input_size, output_buffer, output_size);
                        free(file_hash);
                        return;
                    }
                    free(file_hash);
                }
            }
        }
        
        // Content hash doesn't match or file doesn't exist, store as KV pair
        jetstream_volatile(path, query_strings, method, http_params, input_buffer, input_size, output_buffer, output_size);
        free(content_hash);
        
    } else if (strcmp(method, "DELETE") == 0) {
        // For DELETE, check if file exists and hash matches path
        if (!path || strlen(path) != 69 || path[0] != '/' || strcmp(path + 65, ".dat") != 0) {
            jetstream_volatile(path, query_strings, method, http_params, input_buffer, input_size, output_buffer, output_size);
            return;
        }
        
        char filepath[512];
        int ret = snprintf(filepath, sizeof(filepath), "%s%s", DATA, path);
        if (ret >= (int)sizeof(filepath)) {
            ((char*)output_buffer)[0] = '\0';
            return;
        }
        
        int fd = open(filepath, O_RDONLY);
        if (fd >= 0) {
            // File exists, read and hash it
            char file_buffer[MAX_FILE_SIZE];
            ssize_t bytes_read = read(fd, file_buffer, sizeof(file_buffer));
            close(fd);
            
            if (bytes_read > 0) {
                char* file_hash = sha256_hex(file_buffer, bytes_read);
                if (file_hash) {
                    char expected_path[256];
                    snprintf(expected_path, sizeof(expected_path), "/%s.dat", file_hash);
                    
                    if (strcmp(path, expected_path) == 0) {
                        // Content hash matches path, ignore DELETE request
                        ((char*)output_buffer)[0] = '\0';
                        free(file_hash);
                        return;
                    }
                    free(file_hash);
                }
            }
        }
        
        // Hash doesn't match or file doesn't exist, proceed with delete
        jetstream_volatile(path, query_strings, method, http_params, input_buffer, input_size, output_buffer, output_size);
        
    } else {
        // Unsupported method
        ((char*)output_buffer)[0] = '\0';
    }
}

void jetstream_local(const char* path, const char** query_strings, const char* method,
                     const char** http_params, const void* input_buffer, size_t input_size,
                     void* output_buffer, size_t output_size) {
    // Pass transparently to jetstream_nonvolatile
    jetstream_nonvolatile(path, query_strings, method, http_params, input_buffer, input_size, output_buffer, output_size);
}

void jetstream_restore(const char* path, const char** query_strings, const char* method,
                       const char** http_params, const void* input_buffer, size_t input_size,
                       void* output_buffer, size_t output_size) {
    // For GET requests to /sha256.dat files, try to fetch from backup IPs if file is missing
    if (method && strcmp(method, "GET") == 0 && path && path[0] == '/' && strstr(path, ".dat")) {
        // First check if file exists locally
        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s%s", DATA, strrchr(path, '/'));
        
        FILE* f = fopen(full_path, "rb");
        if (f) {
            // File exists locally, close and use jetstream_local
            fclose(f);
            jetstream_local(path, query_strings, method, http_params, input_buffer, input_size, output_buffer, output_size);
            return;
        }
        
        // File doesn't exist locally, try to restore from backup if within timeout
        if (difftime(time(NULL), startup_time) < WATCHDOG_TIMEOUT) {
            // Try each backup IP randomly
            int indices[NUM_BACKUP_IPS];
            for (int i = 0; i < NUM_BACKUP_IPS; i++) indices[i] = i;
            
            // Simple shuffle
            for (int i = NUM_BACKUP_IPS - 1; i > 0; i--) {
                int j = rand() % (i + 1);
                int temp = indices[i];
                indices[i] = indices[j];
                indices[j] = temp;
            }
            
            for (int i = 0; i < NUM_BACKUP_IPS; i++) {
                const char* backup_ip = BACKUP_IPS[indices[i]];
                char url[512];
                
                if (strchr(backup_ip, '@')) {
                    char ip_part[256];
                    strncpy(ip_part, backup_ip, strchr(backup_ip, '@') - backup_ip);
                    ip_part[strchr(backup_ip, '@') - backup_ip] = '\0';
                    snprintf(url, sizeof(url), "%s%s", ip_part, path);
                } else {
                    snprintf(url, sizeof(url), "%s%s", backup_ip, path);
                }
                
                CURL* curl = curl_easy_init();
                if (!curl) continue;
                
                // Set up response buffer
                struct curl_response response = {0};
                
                // Callback to write response data
                size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
                    size_t realsize = size * nmemb;
                    struct curl_response* mem = (struct curl_response*)userp;
                    
                    void* ptr = realloc(mem->data, mem->size + realsize + 1);
                    if (!ptr) {
                        // Out of memory
                        free(mem->data);
                        mem->data = NULL;
                        mem->size = 0;
                        return 0;
                    }
                    
                    mem->data = ptr;
                    memcpy(&(mem->data[mem->size]), contents, realsize);
                    mem->size += realsize;
                    mem->data[mem->size] = 0;
                    
                    return realsize;
                }
                
                curl_easy_setopt(curl, CURLOPT_URL, url);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
                
                // TLS verification if needed
                if (strstr(backup_ip, "https://") && strchr(backup_ip, '@')) {
                    const char* domain = extract_domain(backup_ip);
                    if (domain) {
                        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
                        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
                    }
                }
                
                CURLcode res = curl_easy_perform(curl);
                long response_code;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
                curl_easy_cleanup(curl);
                
                if (res == CURLE_OK && response_code == 200 && response.data && response.size > 0) {
                    // Save to /data/sha256.dat
                    FILE* save_file = fopen(full_path, "wb");
                    if (save_file) {
                        fwrite(response.data, 1, response.size, save_file);
                        fclose(save_file);
                        
                        // Successfully restored, return the data
                        size_t copy_size = (response.size < output_size) ? response.size : output_size;
                        memcpy(output_buffer, response.data, copy_size);
                        if (copy_size < output_size) {
                            ((char*)output_buffer)[copy_size] = '\0';
                        }
                        free(response.data);
                        return;
                    }
                }
                
                if (response.data) free(response.data);
            }
        }
    }
    
    // Pass through to jetstream_local for normal operation or if restore failed
    jetstream_local(path, query_strings, method, http_params, input_buffer, input_size, output_buffer, output_size);
}

void jetstream_remote(const char* path, const char** query_strings, const char* method,
                      const char** http_params, const void* input_buffer, size_t input_size,
                      void* output_buffer, size_t output_size) {
    // Pass transparently to jetstream_restore
    jetstream_restore(path, query_strings, method, http_params, input_buffer, input_size, output_buffer, output_size);
}

// Helper function to find burst parameter in query strings
int find_burst_parameter(const char** query_strings) {
    if (!query_strings) return 0;
    
    for (int i = 0; query_strings[i]; i++) {
        if (strncmp(query_strings[i], "burst=1", 7) == 0) {
            return 1;
        }
    }
    return 0;
}

// Helper function to find append parameter in query strings
int find_append_parameter(const char** query_strings) {
    if (!query_strings) return 0;
    
    for (int i = 0; query_strings[i]; i++) {
        if (strncmp(query_strings[i], "append=1", 8) == 0) {
            return 1;
        }
    }
    return 0;
}

void jetstream_application(const char* path, const char** query_strings, const char* method,
                           const char** http_params, const void* input_buffer, size_t input_size,
                           void* output_buffer, size_t output_size) {
    // Check for burst mode on PUT/POST requests

    if ((strcmp(method, "PUT") == 0 || strcmp(method, "POST") == 0) && find_burst_parameter(query_strings)) {
        const char* input_ptr = (const char*)input_buffer;
        size_t remaining_input = input_size;
        char sha256_list[MAX_RESPONSE_SIZE];
        memset(sha256_list, 0, sizeof(sha256_list));
        size_t list_pos = 0;
        
        // Process input in 4096-byte blocks
        while (remaining_input > 0) {
            size_t block_size = (remaining_input > 4096) ? 4096 : remaining_input;
            
            // Store this block via jetstream_remote
            char block_response[256];
            memset(block_response, 0, sizeof(block_response));
            
            jetstream_remote(NULL, NULL, method, http_params, input_ptr, block_size, block_response, sizeof(block_response));
            
            // Add SHA256 path to list if valid
            if (strlen(block_response) > 0) {
                // Add newline separator if not first entry
                if (list_pos > 0 && list_pos < sizeof(sha256_list) - 1) {
                    sha256_list[list_pos++] = '\n';
                }
                
                // Add SHA256 path to list
                size_t response_len = strlen(block_response);
                if (list_pos + response_len < sizeof(sha256_list) - 1) {
                    memcpy(sha256_list + list_pos, block_response, response_len);
                    list_pos += response_len;
                }
            }
            
            input_ptr += block_size;
            remaining_input -= block_size;
        }
        
        // Store the collected SHA256 list via jetstream_remote
        jetstream_remote(path, query_strings, method, http_params, sha256_list, list_pos, output_buffer, output_size);
        return;
    }

    // Check for burst mode on GET requests
    if (strcmp(method, "GET") == 0 && find_burst_parameter(query_strings)) {
        // Allocate buffers on heap to avoid stack overflow
        char* file_list = malloc(MAX_RESPONSE_SIZE);
        if (!file_list) {
            ((char*)output_buffer)[0] = '\0';
            return;
        }
        memset(file_list, 0, MAX_RESPONSE_SIZE);
        
        jetstream_remote(path, query_strings, method, http_params, input_buffer, input_size, file_list, MAX_RESPONSE_SIZE);
        
        // Parse newline-separated list and concatenate files
        char* output_ptr = (char*)output_buffer;
        size_t remaining_space = output_size - 1; // Reserve space for null terminator
        size_t total_written = 0;
        
        // Create a copy for safe parsing since strtok modifies the buffer
        char* file_list_copy = malloc(MAX_RESPONSE_SIZE);
        if (!file_list_copy) {
            free(file_list);
            ((char*)output_buffer)[0] = '\0';
            return;
        }
        strncpy(file_list_copy, file_list, MAX_RESPONSE_SIZE - 1);
        file_list_copy[MAX_RESPONSE_SIZE - 1] = '\0';
        
        char* line = strtok(file_list_copy, "\n");
        while (line && remaining_space > 0) {
            // Validate SHA256.dat format
            if (strlen(line) == 69 && line[0] == '/' && strcmp(line + 65, ".dat") == 0) {
                // Validate hex characters
                int valid = 1;
                for (int i = 1; i <= 64; i++) {
                    char c = line[i];
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                        valid = 0;
                        break;
                    }
                }
                
                if (valid) {
                    // Allocate file content buffer on heap
                    char* file_content = malloc(MAX_RESPONSE_SIZE);
                    if (!file_content) {
                        break; // Skip this file if allocation fails
                    }
                    memset(file_content, 0, MAX_RESPONSE_SIZE);
                    
                    jetstream_remote(line, NULL, "GET", NULL, NULL, 0, file_content, MAX_RESPONSE_SIZE);
                    
                    size_t content_len = strlen(file_content);
                    if (content_len > 0 && content_len <= remaining_space) {
                        memcpy(output_ptr, file_content, content_len);
                        output_ptr += content_len;
                        remaining_space -= content_len;
                        total_written += content_len;
                    } else if (content_len > 0 && remaining_space > 0) {
                        // Partial copy if content doesn't fit entirely
                        memcpy(output_ptr, file_content, remaining_space);
                        total_written += remaining_space;
                        remaining_space = 0;
                    }
                    
                    free(file_content);
                }
            }
            
            line = strtok(NULL, "\n");
        }
        
        // Clean up heap allocations
        free(file_list_copy);
        free(file_list);
        
        // Null terminate the concatenated output
        if (total_written < output_size) {
            ((char*)output_buffer)[total_written] = '\0';
        } else if (output_size > 0) {
            ((char*)output_buffer)[output_size - 1] = '\0';
        }
        
        return;
    }
    
    // Pass transparently to jetstream_remote for non-burst requests
    jetstream_remote(path, query_strings, method, http_params, input_buffer, input_size, output_buffer, output_size);
    
    // For GET operations, check if the result is empty and attempt restore if within timeout
    if (strcmp(method, "GET") == 0 && output_buffer && ((char*)output_buffer)[0] == '\0' && 
        difftime(time(NULL), startup_time) < WATCHDOG_TIMEOUT) {
        // Attempt restore for failed GET
        jetstream_restore(path, query_strings, method, http_params, input_buffer, input_size, output_buffer, output_size);
    }
    
    // Check if the response is a write channel for PUT/POST operations
    if ((strcmp(method, "PUT") == 0 || strcmp(method, "POST") == 0) && output_buffer && strlen((char*)output_buffer) > 15) {
        char* response = (char*)output_buffer;
        if (strncmp(response, "Write channel /", 15) == 0) {
            // Extract the target path from "Write channel /sha256.dat"
            char* target_path = response + 14; // Skip "Write channel "
            char* end_marker = strstr(target_path, ".dat");
            if (end_marker && strlen(target_path) >= 69) {
                // Validate target path format
                if (target_path[0] == '/' && strcmp(end_marker, ".dat") == 0) {
                    // Check if target file exists for append operations before redirecting
                    if (find_append_parameter(query_strings)) {
                        char full_path[512];
                        snprintf(full_path, sizeof(full_path), "%s%s", DATA, strrchr(target_path, '/'));
                        struct stat st;
                        if (stat(full_path, &st) != 0 && difftime(time(NULL), startup_time) < WATCHDOG_TIMEOUT) {
                            char restore_buffer[MAX_FILE_SIZE];
                            memset(restore_buffer, 0, sizeof(restore_buffer));
                            jetstream_restore(target_path, NULL, "GET", NULL, NULL, 0, restore_buffer, sizeof(restore_buffer));
                        }
                    }
                    
                    // Call jetstream_remote with the redirected path
                    jetstream_remote(target_path, query_strings, method, http_params, input_buffer, input_size, output_buffer, output_size);
                    // Return the channel path to hide the target
                    format_response_path(NULL, path, (char*)output_buffer, output_size);
                }
            }
        }
    }
    
    // Check if the response is an append channel for PUT/POST operations
    if ((strcmp(method, "PUT") == 0 || strcmp(method, "POST") == 0) && output_buffer && strlen((char*)output_buffer) > 16) {
        char* response = (char*)output_buffer;
        if (strncmp(response, "Append channel /", 16) == 0) {
            // Extract the target path from "Append channel /sha256.dat"
            char* target_path = response + 15; // Skip "Append channel "
            char* end_marker = strstr(target_path, ".dat");
            if (end_marker && strlen(target_path) >= 69) {
                // Validate target path format
                if (target_path[0] == '/' && strcmp(end_marker, ".dat") == 0) {
                    // Check if target file exists before appending
                    char full_path[512];
                    snprintf(full_path, sizeof(full_path), "%s%s", DATA, strrchr(target_path, '/'));
                    struct stat st;
                    if (stat(full_path, &st) != 0 && difftime(time(NULL), startup_time) < WATCHDOG_TIMEOUT) {
                        // Target file doesn't exist, try restore first
                        char restore_buffer[MAX_FILE_SIZE];
                        memset(restore_buffer, 0, sizeof(restore_buffer));
                        jetstream_restore(target_path, NULL, "GET", NULL, NULL, 0, restore_buffer, sizeof(restore_buffer));
                    }
                    
                    // Build query string with append=1 parameter
                    char append_query[512];
                    if (query_strings && query_strings[0] && strlen(query_strings[0]) > 0) {
                        snprintf(append_query, sizeof(append_query), "%s&append=1", query_strings[0]);
                    } else {
                        snprintf(append_query, sizeof(append_query), "append=1");
                    }
                    // Create query string array for jetstream_remote
                    const char* append_query_array[] = {append_query, NULL};
                    // Call jetstream_remote with the redirected path and append=1
                    jetstream_remote(target_path, append_query_array, method, http_params, input_buffer, input_size, output_buffer, output_size);
                    // Return the channel path to hide the target
                    format_response_path(NULL, path, (char*)output_buffer, output_size);
                }
            }
        }
    }
    
    // Check if the response is a read channel for GET operations
    if (strcmp(method, "GET") == 0 && output_buffer && strlen((char*)output_buffer) > 14) {
        char* response = (char*)output_buffer;
        if (strncmp(response, "Read channel /", 14) == 0) {
            // Extract the target path from "Read channel /sha256.dat"
            char* target_path = response + 13; // Skip "Read channel "
            char* end_marker = strstr(target_path, ".dat");
            if (end_marker && strlen(target_path) >= 69) {
                // Validate target path format
                if (target_path[0] == '/' && strcmp(end_marker, ".dat") == 0) {
                    // Call jetstream_remote with the redirected path to get target file content
                    jetstream_remote(target_path, query_strings, method, http_params, input_buffer, input_size, output_buffer, output_size);
                    
                    // If read channel target failed and we got empty result, try restore
                    if (((char*)output_buffer)[0] == '\0' && difftime(time(NULL), startup_time) < WATCHDOG_TIMEOUT) {
                        char restore_buffer[MAX_RESPONSE_SIZE];
                        memset(restore_buffer, 0, sizeof(restore_buffer));
                        jetstream_restore(target_path, query_strings, method, http_params, input_buffer, input_size, restore_buffer, sizeof(restore_buffer));
                        
                        if (strlen(restore_buffer) > 0) {
                            size_t copy_size = (strlen(restore_buffer) < output_size - 1) ? strlen(restore_buffer) : output_size - 1;
                            memcpy(output_buffer, restore_buffer, copy_size);
                            ((char*)output_buffer)[copy_size] = '\0';
                        }
                    }
                    // Do NOT call format_response_path - return the target file content directly
                }
            }
        }
    }
}

int main(int argc, char *argv[]) {
    // Set startup time
    startup_time = time(NULL);

    // Initialize cURL globally for multi-threaded use
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fprintf(stderr, "Failed to initialize cURL\n");
        return 1;
    }

    // Create /data directory if it doesn't exist
    if (mkdir(DATA, 0755) != 0 && errno != EEXIST) {
        perror("Failed to create data directory");
        curl_global_cleanup();
        return 1;
    }

    // Start watchdog thread
    pthread_t watchdog;
    if (pthread_create(&watchdog, NULL, watchdog_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create watchdog thread\n");
        return 1;
    }
    pthread_detach(watchdog);

    // Start server
    jetstream_server();

    // Cleanup cURL
    curl_global_cleanup();

    return 0;
}
