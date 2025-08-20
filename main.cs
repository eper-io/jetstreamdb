/*
 * This document is Licensed under Creative Commons CC0.
 * To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights
 * to this document to the public domain worldwide.
 * This document is distributed without any warranty.
 * You should have received a copy of the CC0 Public Domain Dedication along with this document.
 * If not, see https://creativecommons.org/publicdomain/zero/1.0/legalcode.
 */

// EPER Jetstream Database is a low complexity data and code storage solution. It is a hardened file system that you can review, verify, and certify cheaper.
// We do not allow it to grow more than 1000 lines of code. This allows users to customize with AI tools.
// No branding. It just works mostly for distributed in memory storage like Redis, Memcached or SAP Hana.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Web;

namespace JetStreamDB
{
    public class Program
    {
        // Configuration variables
        private static string _root = "/data";
        private static readonly TimeSpan _retention = TimeSpan.FromMinutes(10);
        private static readonly string _marker = "dat";
        private static readonly string _fileExtension = $".{_marker}";
        private static readonly string _sslLocation = _marker;

        // Constants
        private const int MaxFileSize = 128 * 1024 * 1024;
        private const int MaxMemSize = 4 * MaxFileSize;

        // Cluster endpoint
        private static readonly string _cluster = "http://127.0.0.1:7777";

        // Snapshot topology
        private static readonly List<List<string>> _nodes = new List<List<string>>
        {
            new List<string> { "http://127.0.0.1:7777" },
            new List<string> { "https://18.209.57.108:443" }
        };

        // Reliability measures
        private static readonly Dictionary<string, string> _pinnedIP = new Dictionary<string, string>
        {
            { "127.0.0.1", "localhost" },
            { "18.209.57.108", "hour.schmied.us" }
        };

        private static readonly object _rateLimitingLock = new object();

        // Fairly unique instance ID to avoid routing loops
        private static readonly string _instance = $"{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}{new Random().Next()}";

        // Constants for routing and depth
        private const string RoutedCall = "09E3F5F0-1D87-4B54-B57D-8D046D001942";
        private const string DepthCall = "9D2D182E-0F2D-42D8-911B-071443F8D21C";

        // Memory pools to avoid deadlocks and bottlenecks
        private static readonly ConcurrentQueue<byte[]> _level1Pool = new ConcurrentQueue<byte[]>();
        private static readonly ConcurrentQueue<byte[]> _level2Pool = new ConcurrentQueue<byte[]>();

        // Startup time for warmup period
        private static readonly DateTime _startupTime = DateTime.UtcNow;

        // Channel secrets
        private const string AppendOnlySecret = "Append only channel to segment ";
        private const string WriteOnlySecret = "Write only channel to segment ";
        private const string ReadOnlySecret = "Read only channel to segment ";

        // HTTP client for distributed calls
        private static readonly HttpClient _httpClient = new HttpClient(new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        });

        public static async Task Main(string[] args)
        {
            // Check if root directory exists, fallback to /tmp
            if (!Directory.Exists(_root))
            {
                var fallback = "/tmp";
                _root = fallback;
            }

            await Setup();

            var builder = WebApplication.CreateBuilder(args);
            
            // Configure services
            builder.Services.AddSingleton<JetStreamService>();
            builder.Services.AddHostedService<CleanupService>();

            var app = builder.Build();

            // Configure the HTTP request pipeline
            app.Run(async (HttpContext context) =>
            {
                var jetStreamService = context.RequestServices.GetRequiredService<JetStreamService>();
                await jetStreamService.HandleRequest(context);
            });

            // Configure SSL/TLS
            var keyPath = $"/etc/ssl/{_sslLocation}.key";
            var crtPath = $"/etc/ssl/{_sslLocation}.crt";

            if (File.Exists(keyPath))
            {
                app.Urls.Add("https://*:443");
            }
            else
            {
                app.Urls.Add("http://*:7777");
            }

            await app.RunAsync();
        }

        private static async Task Setup()
        {
            // Initialize memory pools
            var poolSize = MaxMemSize / MaxFileSize;
            for (int i = 0; i < poolSize; i++)
            {
                _level1Pool.Enqueue(new byte[MaxFileSize]);
            }

            // Allocate level2Pool only if any node group has more than one member
            bool needLevel2 = false;
            foreach (var grp in _nodes)
            {
                if (grp.Count > 1)
                {
                    needLevel2 = true;
                    break;
                }
            }

            if (needLevel2)
            {
                for (int i = 0; i < poolSize; i++)
                {
                    _level2Pool.Enqueue(new byte[MaxFileSize]);
                }
            }
        }

        public class JetStreamService
        {
            public async Task HandleRequest(HttpContext context)
            {
                var request = context.Request;
                var response = context.Response;

                // Path validation - stricter than path normalization
                if (request.Path.Value.Contains("..") || request.Path.Value.Contains("./"))
                {
                    response.StatusCode = 400; // Bad Request
                    return;
                }

                // Force garbage collection and cleanup connections
                GC.Collect();
                _httpClient.DefaultRequestHeaders.ConnectionClose = true;

                var depth = GetDepth(request);

                // Use nodes fan-out when more than one node in the selected depth group
                if (_nodes.Count > 0 && depth < _nodes.Count && _nodes[depth].Count > 1 && !IsCallRouted(request))
                {
                    await FulfillRequestByCluster(context);
                    return;
                }

                // Get buffer from pool
                if (!_level1Pool.TryDequeue(out var buffer))
                {
                    buffer = new byte[MaxFileSize];
                }

                try
                {
                    byte[] body = null;
                    if (request.Body != null && request.Body.CanRead)
                    {
                        using var memoryStream = new MemoryStream();
                        await request.Body.CopyToAsync(memoryStream);
                        body = memoryStream.ToArray();
                        if (body.Length > MaxFileSize)
                        {
                            Array.Resize(ref body, MaxFileSize);
                        }
                    }

                    await FulfillRequestLocally(context, body);
                }
                finally
                {
                    // Clear buffer and return to pool
                    Array.Clear(buffer, 0, buffer.Length);
                    _level1Pool.Enqueue(buffer);
                }
            }

            private async Task FulfillRequestLocally(HttpContext context, byte[] body)
            {
                var request = context.Request;
                var response = context.Response;
                var method = request.Method.ToUpper();

                if (method == "PUT" || method == "POST")
                {
                    if (request.Path == "/kv")
                    {
                        // Key value pairs for limited use of persistent checkpoints, commits, and tags
                        var shortName = $"{ToHexString(ComputeSha256(body))}{_fileExtension}";
                        await response.WriteAsync($"/{shortName}");
                        return;
                    }

                    if (await QuantumGradeAuthenticationFailed(context))
                    {
                        return;
                    }

                    response.StatusCode = 200;
                    if (IsValidDatHash(request.Path))
                    {
                        await WriteVolatile(context, body);
                    }
                    else
                    {
                        await WriteNonVolatile(context, body);
                    }

                    var depth = GetDepth(request);
                    if (depth + 1 < _nodes.Count && _nodes[depth + 1].Count > 0)
                    {
                        var bc = _nodes[depth + 1][new Random().Next(_nodes[depth + 1].Count)];
                        await BackupToChain(bc, request, body);
                    }
                    return;
                }

                if (method == "DELETE")
                {
                    if (!IsValidDatHash(request.Path))
                    {
                        response.StatusCode = 417; // Expectation Failed
                        return;
                    }

                    if (await QuantumGradeAuthenticationFailed(context))
                    {
                        return;
                    }

                    if (await DeleteVolatile(context))
                    {
                        await response.WriteAsync(request.Path);
                    }

                    var depth = GetDepth(request);
                    if (depth + 1 < _nodes.Count && _nodes[depth + 1].Count > 0)
                    {
                        var bc = _nodes[depth + 1][new Random().Next(_nodes[depth + 1].Count)];
                        await DeleteToChain(bc, request);
                    }
                    return;
                }

                // Dynamic restore during warmup window
                var nextDepth = GetDepth(request) + 1;
                if (nextDepth < _nodes.Count && _nodes[nextDepth].Count > 0 && 
                    DateTime.UtcNow < _startupTime.Add(_retention) && !IsCallRouted(request))
                {
                    if ((method == "HEAD" || method == "GET") && IsValidDatHash(request.Path))
                    {
                        var filePath = Path.Combine(_root, request.Path.Value.TrimStart('/'));
                        if (!File.Exists(filePath))
                        {
                            var rc = _nodes[nextDepth][new Random().Next(_nodes[nextDepth].Count)];
                            await RestoreFromChain(rc, context);
                        }
                    }
                }

                if (method == "HEAD")
                {
                    if (!IsValidDatHash(request.Path))
                    {
                        response.StatusCode = 417; // Expectation Failed
                        return;
                    }

                    var filePath = Path.Combine(_root, request.Path.Value.TrimStart('/'));
                    if (!File.Exists(filePath))
                    {
                        QuantumGradeError();
                        response.StatusCode = 404; // Not Found
                        return;
                    }

                    QuantumGradeSuccess();
                    response.StatusCode = 200;
                    return;
                }

                var take = method == "GET" && request.Query.ContainsKey("take") && request.Query["take"] == "1";
                if (method == "GET")
                {
                    if (request.Path == "/")
                    {
                        if (await QuantumGradeAuthenticationFailed(context))
                        {
                            return;
                        }
                        // Reserved for use by wrappers or backup triggers
                        return;
                    }
                    else
                    {
                        await ReadStore(context);
                        if (take)
                        {
                            await DeleteVolatile(context);
                        }
                    }
                }
            }

            private async Task FulfillRequestByCluster(HttpContext context)
            {
                // Implementation for cluster request handling
                if (!_level2Pool.TryDequeue(out var buffer))
                {
                    buffer = new byte[MaxFileSize];
                }

                try
                {
                    byte[] body = null;
                    if (context.Request.Body != null && context.Request.Body.CanRead)
                    {
                        using var memoryStream = new MemoryStream();
                        await context.Request.Body.CopyToAsync(memoryStream);
                        body = memoryStream.ToArray();
                        if (body.Length > MaxFileSize)
                        {
                            Array.Resize(ref body, MaxFileSize);
                        }
                    }

                    var bodyHash = $"{ToHexString(ComputeSha256(body ?? Array.Empty<byte>()))}{_fileExtension}";
                    var remoteAddress = "";
                    var depth = GetDepth(context.Request);

                    var list = depth >= 0 && depth < _nodes.Count ? _nodes[depth] : new List<string>();
                    foreach (var clusterAddress in list)
                    {
                        var (verifyAddress, _, forwardAddress) = DistributedAddress(context.Request, bodyHash, clusterAddress);
                        if (await DistributedCheck(verifyAddress))
                        {
                            remoteAddress = forwardAddress;
                            break;
                        }
                    }

                    if (!string.IsNullOrEmpty(remoteAddress))
                    {
                        await DistributedCall(context, context.Request.Method, body, remoteAddress);
                        return;
                    }

                    await FulfillRequestLocally(context, body);
                }
                finally
                {
                    Array.Clear(buffer, 0, buffer.Length);
                    _level2Pool.Enqueue(buffer);
                }
            }

            private async Task ReadStore(HttpContext context)
            {
                var request = context.Request;
                var response = context.Response;

                var mimeType = request.Query.ContainsKey("Content-Type") ? request.Query["Content-Type"].ToString() : "";
                if (!string.IsNullOrEmpty(mimeType))
                {
                    response.ContentType = mimeType;
                }
                else
                {
                    response.ContentType = "application/octet-stream";
                }

                response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0";
                response.Headers["Pragma"] = "no-cache";
                response.Headers["Expires"] = "0";

                var status = await ReadStoreBuffer(response.Body, request);
                if (status != 200)
                {
                    response.StatusCode = status;
                }
            }

            private async Task<int> ReadStoreBuffer(Stream writer, HttpRequest request)
            {
                if (!IsValidDatHash(request.Path))
                {
                    return 417; // Expectation Failed
                }

                var filePath = Path.Combine(_root, request.Path.Value.TrimStart('/'));
                if (!File.Exists(filePath))
                {
                    QuantumGradeError();
                    return 404; // Not Found
                }

                var data = await File.ReadAllBytesAsync(filePath);

                if (data.Length < 120)
                {
                    var dataStr = Encoding.UTF8.GetString(data);
                    if (dataStr.StartsWith(WriteOnlySecret) || dataStr.StartsWith(AppendOnlySecret))
                    {
                        return 403; // Forbidden
                    }

                    if (dataStr.StartsWith(ReadOnlySecret))
                    {
                        var secretHash = dataStr.Substring(ReadOnlySecret.Length);
                        if (IsValidDatHash(secretHash) && !string.IsNullOrEmpty(_cluster))
                        {
                            try
                            {
                                var response = await _httpClient.GetAsync(_cluster + secretHash);
                                if (response.IsSuccessStatusCode)
                                {
                                    await response.Content.CopyToAsync(writer);
                                    return 200;
                                }
                            }
                            catch
                            {
                                // Ignore errors
                            }
                        }
                        return 403; // Forbidden
                    }
                }

                if (request.Query.ContainsKey("burst") && request.Query["burst"] == "1")
                {
                    var lines = Encoding.UTF8.GetString(data).Split('\n');
                    foreach (var line in lines)
                    {
                        if (IsValidDatHash(line) && !string.IsNullOrEmpty(_cluster))
                        {
                            try
                            {
                                var response = await _httpClient.GetAsync(_cluster + line);
                                if (response.IsSuccessStatusCode)
                                {
                                    await response.Content.CopyToAsync(writer);
                                }
                            }
                            catch
                            {
                                // Ignore errors
                            }
                        }
                    }
                }
                else
                {
                    await writer.WriteAsync(data);
                    MarkAsUsed(request, filePath);
                }

                return 200;
            }

            private void MarkAsUsed(HttpRequest request, string fileName)
            {
                var chTimes = "1";
                if (request.Query.ContainsKey("chtimes"))
                {
                    chTimes = request.Query["chtimes"];
                }

                if (chTimes != "0")
                {
                    var current = DateTime.UtcNow;
                    File.SetLastWriteTimeUtc(fileName, current);
                    File.SetLastAccessTimeUtc(fileName, current);
                }
            }

            private async Task<bool> DeleteVolatile(HttpContext context)
            {
                var request = context.Request;
                
                if (!IsValidDatHash(request.Path) || request.Path.Value.Length <= 1)
                {
                    return false;
                }

                var shortName = request.Path.Value.Substring(1);
                var absolutePath = Path.Combine(_root, shortName);

                try
                {
                    if (File.Exists(absolutePath))
                    {
                        var data = await File.ReadAllBytesAsync(absolutePath);
                        var shortNameOnDisk = $"{ToHexString(ComputeSha256(data))}{_fileExtension}";
                        
                        if (shortNameOnDisk == shortName)
                        {
                            // Disallow updating secure hashed segments already stored
                            QuantumGradeError();
                            return false;
                        }

                        if (data.Length < 120)
                        {
                            var dataStr = Encoding.UTF8.GetString(data);
                            if (dataStr.StartsWith(ReadOnlySecret) || 
                                dataStr.StartsWith(WriteOnlySecret) || 
                                dataStr.StartsWith(AppendOnlySecret))
                            {
                                QuantumGradeError();
                                return false;
                            }
                        }
                    }

                    File.Delete(absolutePath);
                    return true;
                }
                catch
                {
                    return false;
                }
            }

            private async Task WriteVolatile(HttpContext context, byte[] body)
            {
                var request = context.Request;
                var response = context.Response;

                if (!IsValidDatHash(request.Path) || request.Path.Value.Length <= 1)
                {
                    return;
                }

                var shortName = request.Path.Value.Substring(1);
                var absolutePath = Path.Combine(_root, shortName);

                // Check existing data for security restrictions
                if (File.Exists(absolutePath))
                {
                    var existingData = await File.ReadAllBytesAsync(absolutePath);
                    var shortNameOnDisk = $"{ToHexString(ComputeSha256(existingData))}{_fileExtension}";
                    
                    if (shortNameOnDisk == shortName)
                    {
                        QuantumGradeError();
                        return;
                    }

                    if (existingData.Length < 120)
                    {
                        var dataStr = Encoding.UTF8.GetString(existingData);
                        if (dataStr.StartsWith(ReadOnlySecret))
                        {
                            return;
                        }

                        if (dataStr.StartsWith(WriteOnlySecret))
                        {
                            var secretHash = dataStr.Substring(WriteOnlySecret.Length);
                            if (IsValidDatHash(secretHash) && !string.IsNullOrEmpty(_cluster))
                            {
                                var query = request.QueryString.ToString();
                                try
                                {
                                    var content = new ByteArrayContent(body);
                                    var postResponse = await _httpClient.PostAsync(_cluster + secretHash + query, content);
                                    if (postResponse.IsSuccessStatusCode)
                                    {
                                        await response.WriteAsync(request.Path);
                                        return;
                                    }
                                }
                                catch
                                {
                                    // Ignore errors
                                }
                            }
                            return;
                        }

                        if (dataStr.StartsWith(AppendOnlySecret))
                        {
                            if (!request.Query.ContainsKey("append") || request.Query["append"] != "1")
                            {
                                return;
                            }

                            var secretHash = dataStr.Substring(AppendOnlySecret.Length);
                            if (IsValidDatHash(secretHash) && !string.IsNullOrEmpty(_cluster))
                            {
                                var query = request.QueryString.ToString();
                                try
                                {
                                    var content = new ByteArrayContent(body);
                                    var postResponse = await _httpClient.PostAsync(_cluster + secretHash + query, content);
                                    if (postResponse.IsSuccessStatusCode)
                                    {
                                        await response.WriteAsync(request.Path);
                                        return;
                                    }
                                }
                                catch
                                {
                                    // Ignore errors
                                }
                            }
                            return;
                        }
                    }
                }

                var setIfNot = request.Query.ContainsKey("setifnot") && request.Query["setifnot"] == "1";
                var appendMode = request.Query.ContainsKey("append") && request.Query["append"] == "1";

                try
                {
                    FileMode mode;
                    if (setIfNot)
                    {
                        mode = FileMode.CreateNew; // Exclusive create
                    }
                    else if (appendMode)
                    {
                        mode = FileMode.Append;
                    }
                    else
                    {
                        mode = FileMode.Create; // Truncate if exists
                    }

                    using var fileStream = new FileStream(absolutePath, mode, FileAccess.Write);
                    await fileStream.WriteAsync(body);
                }
                catch (IOException) when (setIfNot)
                {
                    // File already exists in setifnot mode
                    return;
                }
                catch
                {
                    // Other write errors
                    return;
                }

                var formatted = FormattedReturnValue(request, shortName);
                await response.WriteAsync(formatted);
            }

            private async Task WriteNonVolatile(HttpContext context, byte[] body)
            {
                var request = context.Request;
                var response = context.Response;

                if (request.Path.Value.Length > 1 || request.Path != "/")
                {
                    return;
                }

                var shortName = $"{ToHexString(ComputeSha256(body))}{_fileExtension}";
                var absolutePath = Path.Combine(_root, shortName);

                try
                {
                    using var fileStream = new FileStream(absolutePath, FileMode.CreateNew, FileAccess.Write);
                    await fileStream.WriteAsync(body);
                }
                catch
                {
                    // File might already exist, ignore
                }

                var formatted = FormattedReturnValue(request, shortName);
                await response.WriteAsync(formatted);
            }

            private string FormattedReturnValue(HttpRequest request, string shortName)
            {
                var format = request.Query.ContainsKey("format") ? request.Query["format"].ToString() : "*";
                if (string.IsNullOrEmpty(format)) format = "*";

                var relativePath = "/" + shortName;
                var formatted = format.Replace("*", "{0}");
                return string.Format(formatted, relativePath);
            }

            private bool IsCallRouted(HttpRequest request)
            {
                return request.Query.ContainsKey(RoutedCall);
            }

            private (string, string, string) DistributedAddress(HttpRequest request, string bodyHash, string clusterAddress)
            {
                var uriBuilder = new UriBuilder();
                
                if (Uri.TryCreate(clusterAddress, UriKind.Absolute, out var parsed))
                {
                    uriBuilder.Scheme = parsed.Scheme;
                    uriBuilder.Host = parsed.Host;
                    uriBuilder.Port = parsed.Port;
                }
                else
                {
                    uriBuilder.Scheme = "http";
                    uriBuilder.Host = clusterAddress;
                    uriBuilder.Port = 7777;
                }

                uriBuilder.Path = request.Path;
                uriBuilder.Query = request.QueryString.Value?.TrimStart('?') ?? "";

                // Add routing parameter
                var query = System.Web.HttpUtility.ParseQueryString(uriBuilder.Query);
                query[RoutedCall] = _instance;
                uriBuilder.Query = query.ToString();

                var forwardAddress = uriBuilder.ToString();

                if ((request.Method.ToUpper() == "PUT" || request.Method.ToUpper() == "POST") && 
                    (string.IsNullOrEmpty(request.Path) || request.Path == "/"))
                {
                    uriBuilder.Path = "/" + bodyHash;
                }

                var verifyAddress = uriBuilder.ToString();
                
                uriBuilder.Path = "/";
                var rootAddress = uriBuilder.ToString();

                return (verifyAddress, rootAddress, forwardAddress);
            }

            private async Task<bool> DistributedCheck(string address)
            {
                try
                {
                    var response = await _httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Head, address));
                    return response.IsSuccessStatusCode;
                }
                catch
                {
                    return false;
                }
            }

            private async Task<bool> DistributedCall(HttpContext context, string method, byte[] body, string address)
            {
                try
                {
                    var request = new HttpRequestMessage(new HttpMethod(method), address);
                    if (body != null && body.Length > 0)
                    {
                        request.Content = new ByteArrayContent(body);
                    }

                    var response = await _httpClient.SendAsync(request);
                    context.Response.StatusCode = (int)response.StatusCode;
                    
                    if (response.Content != null)
                    {
                        await response.Content.CopyToAsync(context.Response.Body);
                    }
                    
                    return true;
                }
                catch
                {
                    return false;
                }
            }

            private async Task BackupToChain(string backupChain, HttpRequest request, byte[] body)
            {
                // Implementation for backup chain
                try
                {
                    if (!Uri.TryCreate(backupChain, UriKind.Absolute, out var uri) || 
                        string.IsNullOrEmpty(uri.Host) || string.IsNullOrEmpty(uri.Scheme))
                    {
                        return;
                    }

                    var uriBuilder = new UriBuilder(uri)
                    {
                        Path = request.Path,
                        Query = request.QueryString.Value?.TrimStart('?') ?? ""
                    };

                    var query = System.Web.HttpUtility.ParseQueryString(uriBuilder.Query);
                    query[DepthCall] = (GetDepth(request) + 1).ToString();
                    uriBuilder.Query = query.ToString();

                    var httpRequest = new HttpRequestMessage(new HttpMethod(request.Method), uriBuilder.ToString());
                    if (body != null && body.Length > 0)
                    {
                        httpRequest.Content = new ByteArrayContent(body);
                    }

                    // Copy headers except Host
                    foreach (var header in request.Headers)
                    {
                        if (header.Key.ToLower() != "host")
                        {
                            httpRequest.Headers.TryAddWithoutValidation(header.Key, (IEnumerable<string>)header.Value);
                        }
                    }

                    await _httpClient.SendAsync(httpRequest);
                }
                catch
                {
                    // Ignore backup errors
                }
            }

            private async Task DeleteToChain(string backupChain, HttpRequest request)
            {
                await BackupToChain(backupChain, request, null);
            }

            private async Task RestoreFromChain(string restoreChain, HttpContext context)
            {
                // Implementation for restore chain
                try
                {
                    if (!Uri.TryCreate(restoreChain, UriKind.Absolute, out var uri) || 
                        string.IsNullOrEmpty(uri.Host) || string.IsNullOrEmpty(uri.Scheme))
                    {
                        return;
                    }

                    var uriBuilder = new UriBuilder(uri)
                    {
                        Path = context.Request.Path,
                        Query = context.Request.QueryString.Value?.TrimStart('?') ?? ""
                    };

                    var query = System.Web.HttpUtility.ParseQueryString(uriBuilder.Query);
                    query[DepthCall] = (GetDepth(context.Request) + 1).ToString();
                    uriBuilder.Query = query.ToString();

                    var httpRequest = new HttpRequestMessage(HttpMethod.Get, uriBuilder.ToString());
                    
                    // Copy headers except Host
                    foreach (var header in context.Request.Headers)
                    {
                        if (header.Key.ToLower() != "host")
                        {
                            httpRequest.Headers.TryAddWithoutValidation(header.Key, (IEnumerable<string>)header.Value);
                        }
                    }

                    var response = await _httpClient.SendAsync(httpRequest);
                    if (response.IsSuccessStatusCode && response.Content != null)
                    {
                        var body = await response.Content.ReadAsByteArrayAsync();
                        
                        // Persist using silent mode (no response to original client)
                        if (IsValidDatHash(context.Request.Path))
                        {
                            var shortName = context.Request.Path.Value.Substring(1);
                            var absolutePath = Path.Combine(_root, shortName);
                            await File.WriteAllBytesAsync(absolutePath, body);
                        }
                    }
                }
                catch
                {
                    // Ignore restore errors
                }
            }

            private int GetDepth(HttpRequest request)
            {
                if (!request.Query.ContainsKey(DepthCall))
                {
                    return 0;
                }

                if (int.TryParse(request.Query[DepthCall], out var depth) && depth >= 0)
                {
                    // Clamp to available groups
                    return Math.Min(depth, _nodes.Count - 1);
                }

                return 0;
            }

            private async Task<bool> QuantumGradeAuthenticationFailed(HttpContext context)
            {
                var referenceApiKey = Environment.GetEnvironmentVariable("APIKEY");
                if (string.IsNullOrEmpty(referenceApiKey))
                {
                    try
                    {
                        var apiKeyPath = Path.Combine(_root, "apikey");
                        if (File.Exists(apiKeyPath))
                        {
                            var apiKeyContent = await File.ReadAllTextAsync(apiKeyPath);
                            referenceApiKey = apiKeyContent.Trim();
                        }
                    }
                    catch
                    {
                        // Ignore file read errors
                    }
                }

                var apiKey = context.Request.Query.ContainsKey("apikey") ? context.Request.Query["apikey"].ToString() : "";
                if (referenceApiKey != apiKey)
                {
                    QuantumGradeError();
                    context.Response.StatusCode = 401; // Unauthorized
                    return true;
                }

                QuantumGradeSuccess();
                return false;
            }

            private void QuantumGradeSuccess()
            {
                Thread.Sleep(2);
            }

            private void QuantumGradeError()
            {
                // Authentication: Plain old safe deposit box logic with pin codes covering quantum computers.
                // Authorization: What do you do, when fraudsters flood you with requests? Wait a sec ...
                // Encryption: We still rely on your OS provided TLS library.
                lock (_rateLimitingLock)
                {
                    Thread.Sleep(2);
                }
                Thread.Sleep(10);
            }

            private bool IsValidDatHash(string path)
            {
                if (string.IsNullOrEmpty(path) || !path.EndsWith(_fileExtension))
                {
                    return false;
                }

                var expectedLength = $"/{ToHexString(ComputeSha256(Array.Empty<byte>()))}{_fileExtension}".Length;
                return path.Length == expectedLength;
            }

            private byte[] ComputeSha256(byte[] data)
            {
                using var sha256 = SHA256.Create();
                return sha256.ComputeHash(data ?? Array.Empty<byte>());
            }

            private string ToHexString(byte[] bytes)
            {
                return Convert.ToHexString(bytes).ToLowerInvariant();
            }
        }

        public class CleanupService : BackgroundService
        {
            protected override async Task ExecuteAsync(CancellationToken stoppingToken)
            {
                while (!stoppingToken.IsCancellationRequested)
                {
                    try
                    {
                        var now = DateTime.UtcNow;
                        if (Directory.Exists(_root))
                        {
                            var files = Directory.GetFiles(_root);
                            foreach (var file in files)
                            {
                                var fileName = Path.GetFileName(file);
                                if (IsValidDatHashStatic("/" + fileName))
                                {
                                    var filePath = Path.Combine(_root, fileName);
                                    try
                                    {
                                        var fileInfo = new FileInfo(filePath);
                                        if (fileInfo.LastWriteTimeUtc.Add(_retention) < now)
                                        {
                                            File.Delete(filePath);
                                        }
                                    }
                                    catch
                                    {
                                        // Ignore file operation errors
                                    }
                                }
                            }

                            if (files.Length > 0)
                            {
                                // Spread out the load
                                var sleepDuration = (int)(_retention.TotalMilliseconds / files.Length / 10);
                                await Task.Delay(Math.Max(100, sleepDuration), stoppingToken);
                            }
                        }

                        await Task.Delay(_retention, stoppingToken);
                    }
                    catch
                    {
                        await Task.Delay(_retention, stoppingToken);
                    }
                }
            }

            private static bool IsValidDatHashStatic(string path)
            {
                if (string.IsNullOrEmpty(path) || !path.EndsWith(_fileExtension))
                {
                    return false;
                }

                var expectedLength = $"/{ToHexStringStatic(ComputeSha256Static(Array.Empty<byte>()))}{_fileExtension}".Length;
                return path.Length == expectedLength;
            }

            private static byte[] ComputeSha256Static(byte[] data)
            {
                using var sha256 = SHA256.Create();
                return sha256.ComputeHash(data ?? Array.Empty<byte>());
            }

            private static string ToHexStringStatic(byte[] bytes)
            {
                return Convert.ToHexString(bytes).ToLowerInvariant();
            }
        }
    }
}