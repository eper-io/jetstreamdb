main.e

Create functions jetstream_volatile, jetstream_nonvolatile, jetstream_local, jetstream_restore, jetstream_remote, and jetstream_application with parameters implementing of those of HTTP calls. These are a path, an array of query strings like "key=value", a method, an array of HTTP parameters, an input buffer and size, an output buffer and size. The return value is void. All functions should be empty for now.

Let's create a jetstream_server function that listens to port 443 using the respective tls certificates, if /etc/ssl/jetstream.key and /etc/ssl/jetstream.crt exist. Otherwise it listens to port 7777. The server should handle multiple connections simultaneously.

The handler should read HTTP requests, and call jetstream_application with the request body as input buffer, decoded query arguments, method, http parameters returning the output buffer from jetstream_application as body.

jetstream_application should pass these transparently to jetstream_remote and pass back the output body. jetstream_remote should pass these transparently to jetstream_restore,jetstream_local, jetstream_nonvolatile, jetstream_volatile pass back the output body.

Make sure that you add function prototypes correctly at the beginning.

---

jetstream_local should get the path and the body. It should verify that it is in the format of /sha256.dat, where sha256 is the sha256 hash of the input buffer. If the hash matches or this is a PUT to NULL, empty string or /, then we pass to a jetstream_nonvolatile function. Otherwise we pass to a jetstream_volatile function of the same type. If the hash does not match the content or the file does not exist, we call jetstream_volatile with all the parameters.

Make sure to import the right libraries, so that the code builds.

---

Make sure that the data directory is /data coming from #define DATA "/data"

Implement jetstream_nonvolatile. PUT and POST should save the content. This will happen only once since we called the function when the hash matched or this is a special put. If successful, the returned body is the sha256 hash of the content like /sha256.dat. GET should return the content. DELETE should return an empty string and keep the file untouched.

Implement jetstream_volatile. PUT and POST should save the content. Open the file with O_CREATE and O_TRUNC to make sure it gets the right content. If successful, the returned body is the sha256 hash of the path in the request like /sha256.dat. Do not allow any other format than this in the path. GET should return the content. DELETE should unlink the file and return the path in the request like /sha256.dat. If the file did not exist, it should return an empty string.

---

jetstream_volatile should handle creating or truncating the file and saving it on, PUT, POST. This returns the /sha.dat relative file path to /data.  It returns error if the path is not in /sha256.dat format. GET reads and returns the file stored in the output buffer. DELETE should unlink. If the file was deleted and existed, it returns the /sha256.dat in the output buffer. Any error should just return an empty string.

---

Implement formatting of the response path in jetstream_volatile. If there is a query parameter like format=http://example.com%s, then replace %s %25s or * with the /sha256.dat path.

Make sure that we are secure without buffer overflows.

---

Implement jetstream_nonvolatile. This is a special function that filters the calls to jetstream_volatile. We hash the content to be written on PUT and PUSH. If the path is NULL, empty, or / then we call jetstream_volatile with a changed path of the content's /sha256.dat. If the path pf PUT, POST is a valid hash and it is the same as the content hash, we call jetstream_volatile with this path. Otherwise we read back the file of PUT, POST, DELETE relative to /data based on the path and get a sha256. If the sha256 of the content stored and the path /sha256.dat matches, we ignore the content PUT and any delete request. If the content hash already stored does not match the sha256 path, we call jetstream_volatile to store as KV pair.

jetstream_nonvolatile just forwards GET and HEAD requests.

---

Change jetstream_application. If there is a query parameter like burst=1 on GET, then we should call jetstream_remote with the same parameters. Interpret the result as a newline separated list of /sha256.dat values. Read each valid value and return a concatentated output buffer. Make sure that we do not read the files directly but call jetstream_remote for each chunk file of the burst.

---

Implement burst writes with PUT, POST in jetstream_application. If there is a query parameter like burst=1 on PUT, POST, then we should call jetstream_remote on every single 4096 byte block read returning a /sha256.dat value. Collect these as a newline separated list and store them as well with jetstream_remote, returning the result of this final call.

---

Implement jetstream_volatile with append=1. If we have a PUT, PUSH, and we have a query parameter like append=1, then we should open the file with O_APPEND and write the content to it. If successful, the returned body is the sha256 hash of the path in the request like /sha256.dat. Do not allow any other format than this in the path. If the file did not exist, we should create and return the request path.

---

Implement jetstream_volatile with take=1. Open the file and read the content, and then delete atomically. Return the content of the file in the output buffer. If the file did not exist, return an empty string. If the file existed, delete it and return content before deletion in the output buffer.

---

Create a watchdog thread that runs an iteration that waits for sixty seconds after every run. It should check the modificiation time of the file and if it is older than sixty seconds, it should delete the file regardless of volatility.
The sixty seconds watchdog should be a constant next to the file size constant.

Both reading a file and writing a file should reset the file modification time.

---

The file size on disk should be limited to 1 megabytes that is a constant in the top of the file.

---

Are there any potential buffer overflows or memory leaks in the code? Please fix them all.

---

Implement channel write. Channel write is a file that directs writes to another file. Let's read back all files before we do a PUT or POST in jetstream_volatile. If the buffer is like 'Write channel /sha256.dat', then this is a write channel. Do not continue writing, but return this content from jetstream_volatile 'Write channel /sha256.dat'. Then change the end of jetstream_application. Verify the content returned. If it is 'Write channel /sha256.dat', then write call jetstream_remote chaning the path to /sha256.dat appending any query parameters from outside.

Change the GET path in jetstream_volatile to return empty string, if the pattern is a write channel.

Do not allow the deletion of a write channel. It can only be cleaned up in the watchdog thread.

---

Read channels are files that redirect reads to another file. If the buffer is like 'Read channel /sha256.dat', then this is a read channel. Read channels cannot be deleted or written into, only cleaned up by the watchdog thread. They return the content of the file pointed to from jetstream_application, and they implement protections in jetstream_volatile.

For GET requests in jetstream_volatile, if the pattern is a read channel, return the channel content for redirection. In jetstream_application, verify the content returned. If it is 'Read channel /sha256.dat', then call jetstream_remote with GET method changing the path to /sha256.dat.

Do not allow PUT/POST operations on read channels - return empty string. Do not allow deletion of read channels. They can only be cleaned up in the watchdog thread.

Please implement the jetstream_application Read channel behavior similar to PUT and POST forwarding the read call to the target path.

---

Make sure that there are no memory leaks in the code, and it is reliable running for months without restart.

---

Fix any potential buffer overflows proactively.

---
