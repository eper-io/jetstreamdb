#!/usr/bin/env python3
"""
JetStream Database Server
A high-performance database server with HTTP API interface
"""

import os
import ssl
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Optional, Tuple, Any
import json
import hashlib
import re
import time

DATA = "/data"
# File and cleanup constants
MAX_FILE_SIZE = 1_048_576  # 1 MiB limit (not strictly enforced in all paths yet)
WATCHDOG_TTL_SECONDS = 60  # Files older than this will be deleted by watchdog


# Function Prototypes
def jetstream_volatile(path: str, query_strings: List[str], method: str, 
                      http_params: List[str], input_buffer: bytes, 
                      input_size: int, output_buffer: bytearray, 
                      output_size: int) -> None:
    """Handle volatile storage operations"""
    pass


def jetstream_nonvolatile(path: str, query_strings: List[str], method: str,
                         http_params: List[str], input_buffer: bytes,
                         input_size: int, output_buffer: bytearray,
                         output_size: int) -> None:
    """Handle non-volatile storage operations"""
    pass


def jetstream_local(path: str, query_strings: List[str], method: str,
                   http_params: List[str], input_buffer: bytes,
                   input_size: int, output_buffer: bytearray,
                   output_size: int) -> None:
    """Handle local storage operations"""
    pass


def jetstream_restore(path: str, query_strings: List[str], method: str,
                     http_params: List[str], input_buffer: bytes,
                     input_size: int, output_buffer: bytearray,
                     output_size: int) -> None:
    """Handle restore operations"""
    pass


def jetstream_remote(path: str, query_strings: List[str], method: str,
                    http_params: List[str], input_buffer: bytes,
                    input_size: int, output_buffer: bytearray,
                    output_size: int) -> None:
    """Handle remote operations - passes through to restore, local, nonvolatile, volatile"""
    pass


def jetstream_application(path: str, query_strings: List[str], method: str,
                         http_params: List[str], input_buffer: bytes,
                         input_size: int, output_buffer: bytearray,
                         output_size: int) -> None:
    """Application layer - passes through to jetstream_remote"""
    pass


def jetstream_server() -> None:
    """Main server function that handles TLS/HTTP connections"""
    pass


# Implementation of JetStream functions
def jetstream_volatile(path: str, query_strings: List[str], method: str, 
                      http_params: List[str], input_buffer: bytes, 
                      input_size: int, output_buffer: bytearray, 
                      output_size: int) -> None:
    """Handle volatile storage operations"""
    try:
        # Helpers
        def validate_sha_path(p: str) -> Optional[str]:
            m = re.fullmatch(r"/([0-9a-fA-F]{64})\.dat", p or "")
            return m.group(1).lower() if m else None

        def full_path_from_rel(rel_path: str) -> str:
            # Ensure we never escape DATA
            rel = rel_path.lstrip("/\\")
            return os.path.join(DATA, rel)

        def get_format_template(qs: List[str]) -> Optional[str]:
            for item in qs or []:
                if "=" in item:
                    k, v = item.split("=", 1)
                else:
                    k, v = item, ""
                if k == "format":
                    return v
            return None

        def apply_format(path_value: str, fmt: Optional[str]) -> bytes:
            if not fmt:
                return path_value.encode("ascii", errors="ignore")
            # Replace placeholders with the path
            formatted = fmt.replace("%25s", path_value).replace("%s", path_value).replace("*", path_value)
            return formatted.encode("utf-8", errors="ignore")

        def read_small(path: str, limit: int = 256) -> Optional[bytes]:
            try:
                with open(path, "rb") as f:
                    return f.read(limit)
            except FileNotFoundError:
                return None
            except Exception:
                return None

        def parse_write_channel(buf: bytes) -> Optional[str]:
            try:
                txt = (buf or b"").decode('utf-8', errors='ignore').strip()
            except Exception:
                return None
            m = re.fullmatch(r"Write channel\s+(/([0-9a-fA-F]{64})\.dat)", txt)
            return m.group(1) if m else None

        def parse_read_channel(buf: bytes) -> Optional[str]:
            try:
                txt = (buf or b"").decode('utf-8', errors='ignore').strip()
            except Exception:
                return None
            m = re.fullmatch(r"Read channel\s+(/([0-9a-fA-F]{64})\.dat)", txt)
            return m.group(1) if m else None

        def parse_append_channel(buf: bytes) -> Optional[str]:
            try:
                txt = (buf or b"").decode('utf-8', errors='ignore').strip()
            except Exception:
                return None
            m = re.fullmatch(r"Append channel\s+(/([0-9a-fA-F]{64})\.dat)", txt)
            return m.group(1) if m else None

        method_upper = (method or "").upper()
        incoming_hash = validate_sha_path(path or "")
        if not incoming_hash:
            # Only allow /sha256.dat format
            return

        target_rel = f"/{incoming_hash}.dat"
        target_full = full_path_from_rel(target_rel)

        if method_upper in ("PUT", "POST", "PUSH"):
            # Check for append=1 behavior
            append_flag = False
            for item in query_strings or []:
                if "=" in item:
                    k, v = item.split("=", 1)
                else:
                    k, v = item, ""
                if k == "append" and v == "1":
                    append_flag = True
                    break

            # If target file is an existing write channel, do not write; return marker
            existing_bytes = read_small(target_full)
            # Block writes to existing write/read channels
            existing_write_target = parse_write_channel(existing_bytes) if existing_bytes is not None else None
            existing_read_target = parse_read_channel(existing_bytes) if existing_bytes is not None else None
            existing_append_target = parse_append_channel(existing_bytes) if existing_bytes is not None else None
            if existing_write_target:
                # Return the channel content for redirection
                marker = existing_bytes.decode('utf-8', errors='ignore').strip()
                marker_bytes = marker.encode('utf-8')
                n = min(len(marker_bytes), output_size)
                output_buffer[:n] = marker_bytes[:n]
                return
            if existing_append_target:
                # Return the channel content for redirection
                marker = existing_bytes.decode('utf-8', errors='ignore').strip()
                marker_bytes = marker.encode('utf-8')
                n = min(len(marker_bytes), output_size)
                output_buffer[:n] = marker_bytes[:n]
                return
            if existing_read_target:
                # Do not allow writing into read channel
                return

            # If the incoming buffer is a write-channel declaration, store it and return the request path
            incoming_channel_target = parse_write_channel(input_buffer or b"")
            if incoming_channel_target and not append_flag:
                os.makedirs(DATA, exist_ok=True)
                # Store the declaration (capped size)
                to_write = (input_buffer or b"")[:MAX_FILE_SIZE]
                with open(target_full, "wb") as f:
                    if to_write:
                        f.write(to_write)
                try:
                    os.utime(target_full, None)
                except Exception:
                    pass
                # Return the channel file path
                fmt = get_format_template(query_strings)
                result_bytes = apply_format(target_rel, fmt)
                n = min(len(result_bytes), output_size)
                output_buffer[:n] = result_bytes[:n]
                return

            # If incoming buffer declares a read channel, store it and return the request path
            incoming_read_target = parse_read_channel(input_buffer or b"")
            if incoming_read_target and not append_flag:
                os.makedirs(DATA, exist_ok=True)
                to_write = (input_buffer or b"")[:MAX_FILE_SIZE]
                with open(target_full, "wb") as f:
                    if to_write:
                        f.write(to_write)
                try:
                    os.utime(target_full, None)
                except Exception:
                    pass
                # Return the channel file path
                fmt = get_format_template(query_strings)
                result_bytes = apply_format(target_rel, fmt)
                n = min(len(result_bytes), output_size)
                output_buffer[:n] = result_bytes[:n]
                return

            # If incoming buffer declares an append channel, store it and return the request path
            incoming_append_target = parse_append_channel(input_buffer or b"")
            if incoming_append_target and not append_flag:
                os.makedirs(DATA, exist_ok=True)
                to_write = (input_buffer or b"")[:MAX_FILE_SIZE]
                with open(target_full, "wb") as f:
                    if to_write:
                        f.write(to_write)
                try:
                    os.utime(target_full, None)
                except Exception:
                    pass
                # Return the channel file path
                fmt = get_format_template(query_strings)
                result_bytes = apply_format(target_rel, fmt)
                n = min(len(result_bytes), output_size)
                output_buffer[:n] = result_bytes[:n]
                return

            # Create or truncate and write (normal behavior)
            os.makedirs(DATA, exist_ok=True)
            if append_flag:
                existed = os.path.exists(target_full)
                # Determine how much we can append without exceeding MAX_FILE_SIZE
                current_size = 0
                if existed:
                    try:
                        current_size = os.path.getsize(target_full)
                    except OSError:
                        current_size = 0
                remaining_cap = max(0, MAX_FILE_SIZE - current_size)
                to_write = (input_buffer or b"")[:remaining_cap]
                with open(target_full, "ab") as f:
                    if to_write:
                        f.write(to_write)
                # Touch file to refresh mtime after write
                try:
                    os.utime(target_full, None)
                except Exception:
                    pass
                # Return the request path (optionally formatted)
                fmt = get_format_template(query_strings)
                result_bytes = apply_format(target_rel, fmt)
                n = min(len(result_bytes), output_size)
                output_buffer[:n] = result_bytes[:n]
            else:
                # Overwrite with capped size
                to_write = (input_buffer or b"")[:MAX_FILE_SIZE]
                with open(target_full, "wb") as f:
                    if to_write:
                        f.write(to_write)
                # Touch after write
                try:
                    os.utime(target_full, None)
                except Exception:
                    pass
                # Return the request path (relative /sha256.dat), optionally formatted
                fmt = get_format_template(query_strings)
                result_bytes = apply_format(target_rel, fmt)
                n = min(len(result_bytes), output_size)
                output_buffer[:n] = result_bytes[:n]
            return

        elif method_upper in ("GET", "HEAD"):
            # Check for take=1 which reads and then deletes the file
            take_flag = False
            for item in query_strings or []:
                if "=" in item:
                    k, v = item.split("=", 1)
                else:
                    k, v = item, ""
                if k == "take" and v == "1":
                    take_flag = True
                    break
            try:
                with open(target_full, "rb") as f:
                    data = f.read(output_size)
                # If this file is a write channel, return empty string on GET/HEAD
                channel_target = parse_write_channel(data)
                if channel_target:
                    return
                # If this file is a read channel, return the marker for application to redirect
                read_target = parse_read_channel(data)
                if read_target:
                    marker = f"Read channel {read_target}".encode('utf-8')
                    n = min(len(marker), output_size)
                    output_buffer[:n] = marker[:n]
                    return
                # Touch after read
                try:
                    os.utime(target_full, None)
                except Exception:
                    pass
                if take_flag:
                    # Attempt to delete after read
                    try:
                        os.remove(target_full)
                    except FileNotFoundError:
                        pass
                output_buffer[:len(data)] = data
            except FileNotFoundError:
                # Return empty if not exists
                return
            return

        elif method_upper == "DELETE":
            # Prevent deletion of write/read/append channel files
            existing_bytes = read_small(target_full)
            existing_write_target = parse_write_channel(existing_bytes) if existing_bytes is not None else None
            existing_read_target = parse_read_channel(existing_bytes) if existing_bytes is not None else None
            existing_append_target = parse_append_channel(existing_bytes) if existing_bytes is not None else None
            if existing_write_target or existing_read_target or existing_append_target:
                return
            try:
                os.remove(target_full)
                # Return the request path (optionally formatted)
                fmt = get_format_template(query_strings)
                result_bytes = apply_format(target_rel, fmt)
                n = min(len(result_bytes), output_size)
                output_buffer[:n] = result_bytes[:n]
            except FileNotFoundError:
                # Return empty string if did not exist
                return
            return

        else:
            # Unsupported -> empty
            return
    except Exception:
        # Any error -> empty
        return


def jetstream_nonvolatile(path: str, query_strings: List[str], method: str,
                         http_params: List[str], input_buffer: bytes,
                         input_size: int, output_buffer: bytearray,
                         output_size: int) -> None:
    """Handle non-volatile storage operations"""
    try:
        # Helpers
        def validate_sha_path(p: str) -> Optional[str]:
            m = re.fullmatch(r"/([0-9a-fA-F]{64})\.dat", p or "")
            return m.group(1).lower() if m else None

        def full_path_from_rel(rel_path: str) -> str:
            # Ensure we never escape DATA
            rel = rel_path.lstrip("/\\")
            return os.path.join(DATA, rel)

        method_upper = (method or "").upper()

        # Forward GET/HEAD requests unchanged
        if method_upper in ("GET", "HEAD"):
            jetstream_volatile(path, query_strings, method, http_params,
                               input_buffer, input_size, output_buffer, output_size)
            return

        # PUT/POST filtering logic
        if method_upper in ("PUT", "POST"):
            content_hash = hashlib.sha256(input_buffer or b"").hexdigest()

            # If path empty or root -> store under content hash path
            if not path or path == "/":
                new_path = f"/{content_hash}.dat"
                jetstream_volatile(new_path, query_strings, method, http_params,
                                   input_buffer, input_size, output_buffer, output_size)
                return

            incoming_hash = validate_sha_path(path)
            if not incoming_hash:
                # Invalid path format for key -> do nothing (safer than forcing a write)
                return

            if incoming_hash == content_hash:
                # Path matches content hash -> write via volatile to that path
                jetstream_volatile(path, query_strings, method, http_params,
                                   input_buffer, input_size, output_buffer, output_size)
                return

            # Mismatch: inspect existing stored content at key path
            target_full = full_path_from_rel(path)
            try:
                with open(target_full, "rb") as f:
                    existing = f.read(1024 * 1024 + 1)  # read up to 1MB+1; size limits handled elsewhere
                # Touch mtime after read
                try:
                    os.utime(target_full, None)
                except Exception:
                    pass
                stored_hash = hashlib.sha256(existing).hexdigest()
                if stored_hash == incoming_hash:
                    # Key points to immutable content already; ignore put
                    return
                else:
                    # Key is mutable KV: write new value under the key path
                    jetstream_volatile(path, query_strings, method, http_params,
                                       input_buffer, input_size, output_buffer, output_size)
                    return
            except FileNotFoundError:
                # No existing value for key: treat as KV store write
                jetstream_volatile(path, query_strings, method, http_params,
                                   input_buffer, input_size, output_buffer, output_size)
                return

        # DELETE filtering logic
        if method_upper == "DELETE":
            incoming_hash = validate_sha_path(path or "")
            if not incoming_hash:
                return
            target_full = full_path_from_rel(path)
            try:
                with open(target_full, "rb") as f:
                    existing = f.read(1024 * 1024 + 1)
                # Touch mtime after read
                try:
                    os.utime(target_full, None)
                except Exception:
                    pass
                stored_hash = hashlib.sha256(existing).hexdigest()
                if stored_hash == incoming_hash:
                    # Immutable content: ignore delete
                    return
                else:
                    # Mutable KV: allow delete via volatile
                    jetstream_volatile(path, query_strings, method, http_params,
                                       input_buffer, input_size, output_buffer, output_size)
                    return
            except FileNotFoundError:
                # Nothing to delete; forward to volatile to maintain semantics (returns empty)
                jetstream_volatile(path, query_strings, method, http_params,
                                   input_buffer, input_size, output_buffer, output_size)
                return

        # Other methods -> empty
        return
    except Exception:
        # On any error, return empty
        return


def jetstream_local(path: str, query_strings: List[str], method: str,
                   http_params: List[str], input_buffer: bytes,
                   input_size: int, output_buffer: bytearray,
                   output_size: int) -> None:
    """Handle local storage operations"""
    try:
        method_upper = (method or "").upper()
        req_path = path or ""

        # If this is a PUT to null/empty root path, pass to nonvolatile
        if method_upper == "PUT" and (req_path == "" or req_path == "/"):
            jetstream_nonvolatile(path, query_strings, method, http_params,
                                  input_buffer, input_size, output_buffer, output_size)
            return

        # Validate path format: /<sha256>.dat
        m = re.fullmatch(r"/([0-9a-fA-F]{64})\.dat", req_path)
        if m:
            # For GET/HEAD/DELETE on hashed paths, always go through nonvolatile
            if method_upper in ("GET", "HEAD", "DELETE"):
                jetstream_nonvolatile(path, query_strings, method, http_params,
                                      input_buffer, input_size, output_buffer, output_size)
                return

            # For writes, if body present and matches path hash -> nonvolatile; else volatile
            if method_upper in ("PUT", "POST", "PUSH"):
                if input_size and input_buffer is not None:
                    body_sha = hashlib.sha256(input_buffer).hexdigest()
                    if body_sha.lower() == m.group(1).lower():
                        # Hash matches content -> treat as nonvolatile
                        jetstream_nonvolatile(path, query_strings, method, http_params,
                                              input_buffer, input_size, output_buffer, output_size)
                        return
                # Hash does not match content -> volatile
                jetstream_volatile(path, query_strings, method, http_params,
                                   input_buffer, input_size, output_buffer, output_size)
                return

            # Other methods on hashed path default to nonvolatile
            jetstream_nonvolatile(path, query_strings, method, http_params,
                                  input_buffer, input_size, output_buffer, output_size)
            return

        # Path not in /sha256.dat format -> volatile
        jetstream_volatile(path, query_strings, method, http_params,
                           input_buffer, input_size, output_buffer, output_size)
    except Exception:
        # On any error, fall back to volatile handling
        jetstream_volatile(path, query_strings, method, http_params,
                           input_buffer, input_size, output_buffer, output_size)


def jetstream_restore(path: str, query_strings: List[str], method: str,
                     http_params: List[str], input_buffer: bytes,
                     input_size: int, output_buffer: bytearray,
                     output_size: int) -> None:
    """Handle restore operations"""
    # Empty implementation as requested
    pass


def jetstream_remote(path: str, query_strings: List[str], method: str,
                    http_params: List[str], input_buffer: bytes,
                    input_size: int, output_buffer: bytearray,
                    output_size: int) -> None:
    """Handle remote operations - passes through to restore, local, nonvolatile, volatile"""
    # Delegate to local, which decides volatile vs nonvolatile.
    jetstream_local(path, query_strings, method, http_params,
                   input_buffer, input_size, output_buffer, output_size)


def jetstream_application(path: str, query_strings: List[str], method: str,
                         http_params: List[str], input_buffer: bytes,
                         input_size: int, output_buffer: bytearray,
                         output_size: int) -> None:
    """Application layer - passes through to jetstream_remote"""
    # Burst GET handling: if burst=1 query param on GET, treat body as list of paths
    try:
        method_upper = (method or "").upper()

        def has_burst(qs: List[str]) -> bool:
            for item in qs or []:
                if "=" in item:
                    k, v = item.split("=", 1)
                else:
                    k, v = item, ""
                if k == "burst" and v == "1":
                    return True
            return False

        def remove_burst(qs: List[str]) -> List[str]:
            res: List[str] = []
            for item in qs or []:
                if "=" in item:
                    k, v = item.split("=", 1)
                else:
                    k, v = item, ""
                if not (k == "burst" and v == "1"):
                    res.append(item)
            return res

        if method_upper == "GET" and has_burst(query_strings):
            # First, get the index content via remote into a temporary buffer
            tmp_index = bytearray(output_size)
            jetstream_remote(path, query_strings, method, http_params,
                             input_buffer, input_size, tmp_index, output_size)

            # Extract actual length up to first null byte
            try:
                idx_len = tmp_index.index(0)
            except ValueError:
                idx_len = len(tmp_index)
            index_text = tmp_index[:idx_len].decode('utf-8', errors='ignore')

            # Prepare to concatenate chunks
            remaining = output_size
            write_pos = 0
            chunk_qs = remove_burst(query_strings)

            # Iterate over each valid /sha256.dat line
            for line in index_text.splitlines():
                line = line.strip()
                if not re.fullmatch(r"/([0-9a-fA-F]{64})\.dat", line or ""):
                    continue
                if remaining <= 0:
                    break
                # Fetch this chunk via remote call
                tmp_chunk = bytearray(remaining)
                jetstream_remote(line, chunk_qs, "GET", http_params,
                                 b"", 0, tmp_chunk, remaining)
                # Determine content length up to first null
                try:
                    chunk_len = tmp_chunk.index(0)
                except ValueError:
                    chunk_len = len(tmp_chunk)
                if chunk_len <= 0:
                    continue
                # Copy into output buffer
                end_pos = write_pos + chunk_len
                output_buffer[write_pos:end_pos] = tmp_chunk[:chunk_len]
                write_pos = end_pos
                remaining = output_size - write_pos
            return

        # Burst write handling for PUT/POST
        if method_upper in ("PUT", "POST") and has_burst(query_strings):
            # Split input_buffer into 4096-byte blocks and store each via remote
            BLOCK_SIZE = 4096
            index_lines: list[str] = []
            # Iterate over the input buffer length as indicated by input_size
            offset = 0
            while offset < input_size:
                end = min(offset + BLOCK_SIZE, input_size)
                chunk = input_buffer[offset:end]
                offset = end
                # Store this chunk via remote with empty path (special put handled downstream)
                tmp_resp = bytearray(256)  # response should be a short path
                jetstream_remote("", remove_burst(query_strings), method, http_params,
                                 chunk, len(chunk), tmp_resp, len(tmp_resp))
                # Determine response text up to first null
                try:
                    resp_len = tmp_resp.index(0)
                except ValueError:
                    resp_len = len(tmp_resp)
                resp_text = tmp_resp[:resp_len].decode('utf-8', errors='ignore').strip()
                # Accept only valid /sha256.dat entries
                if re.fullmatch(r"/([0-9a-fA-F]{64})\.dat", resp_text or ""):
                    index_lines.append(resp_text)
                else:
                    # If any chunk write fails to return a valid path, abort with empty output
                    return

            # Compose newline-separated index
            index_body = ("\n".join(index_lines)).encode('utf-8')

            # Store the index at the original path via remote (without burst param)
            tmp_final = bytearray(output_size)
            jetstream_remote(path, remove_burst(query_strings), method, http_params,
                             index_body, len(index_body), tmp_final, output_size)
            # Copy the final response into output_buffer
            try:
                final_len = tmp_final.index(0)
            except ValueError:
                final_len = len(tmp_final)
            n = min(final_len, output_size)
            output_buffer[:n] = tmp_final[:n]
            return

        # Default: pass through transparently to jetstream_remote
        jetstream_remote(path, query_strings, method, http_params,
                         input_buffer, input_size, output_buffer, output_size)

        # After a write, check if we hit a write channel and need to redirect
        if method_upper in ("PUT", "POST", "PUSH"):
            # Determine current output length
            try:
                out_len = output_buffer.index(0)
            except ValueError:
                out_len = output_size
            marker_text = output_buffer[:out_len].decode('utf-8', errors='ignore').strip()
            
            # Check for write channel redirection
            m = re.fullmatch(r"Write channel\s+(/([0-9a-fA-F]{64})\.dat)", marker_text)
            if m:
                target_path = m.group(1)
                # Perform redirected write to the target path with original body and query params
                # Use a temporary buffer to capture the redirected response, then copy back
                tmp = bytearray(output_size)
                jetstream_remote(target_path, query_strings, method, http_params,
                                 input_buffer, input_size, tmp, output_size)
                # After successful redirection, return the channel path instead of target path
                channel_path_bytes = path.encode('utf-8')
                n = min(len(channel_path_bytes), output_size)
                output_buffer[:n] = channel_path_bytes[:n]
                # If channel path shorter than previous, zero out the rest to keep terminator
                if n < output_size:
                    output_buffer[n:n+1] = b"\x00"
                return
            
            # Check for append channel redirection
            m = re.fullmatch(r"Append channel\s+(/([0-9a-fA-F]{64})\.dat)", marker_text)
            if m:
                target_path = m.group(1)
                # Perform redirected append to the target path with original body and query params
                # Add append=1 to the query strings for the redirected call
                append_query = list(query_strings or [])
                append_query.append("append=1")
                tmp = bytearray(output_size)
                jetstream_remote(target_path, append_query, method, http_params,
                                 input_buffer, input_size, tmp, output_size)
                # After successful redirection, return the channel path instead of target path
                channel_path_bytes = path.encode('utf-8')
                n = min(len(channel_path_bytes), output_size)
                output_buffer[:n] = channel_path_bytes[:n]
                # If channel path shorter than previous, zero out the rest to keep terminator
                if n < output_size:
                    output_buffer[n:n+1] = b"\x00"

        # After a read, check if we hit a read channel and need to redirect
        if method_upper in ("GET", "HEAD"):
            try:
                out_len = output_buffer.index(0)
            except ValueError:
                out_len = output_size
            marker_text = output_buffer[:out_len].decode('utf-8', errors='ignore').strip()
            m = re.fullmatch(r"Read channel\s+(/([0-9a-fA-F]{64})\.dat)", marker_text)
            if m:
                target_path = m.group(1)
                tmp = bytearray(output_size)
                jetstream_remote(target_path, query_strings, "GET", http_params,
                                 b"", 0, tmp, output_size)
                try:
                    n = tmp.index(0)
                except ValueError:
                    n = len(tmp)
                n = min(n, output_size)
                output_buffer[:n] = tmp[:n]
                if n < output_size:
                    output_buffer[n:n+1] = b"\x00"
        
    except Exception:
        # On any error, fall back to transparent pass-through
        jetstream_remote(path, query_strings, method, http_params,
                         input_buffer, input_size, output_buffer, output_size)
class JetStreamHandler(BaseHTTPRequestHandler):
    """HTTP request handler for JetStream database operations"""
    
    def _handle_request(self) -> None:
        """Common request handling logic"""
        try:
            # Parse the URL and query parameters
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            query_params = parse_qs(parsed_url.query)
            
            # Convert query parameters to list of "key=value" strings
            query_strings = []
            for key, values in query_params.items():
                for value in values:
                    query_strings.append(f"{key}={value}")
            
            # Get HTTP headers as parameters
            http_params = []
            for header, value in self.headers.items():
                http_params.append(f"{header}={value}")
            
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            input_buffer = self.rfile.read(content_length) if content_length > 0 else b''
            input_size = len(input_buffer)
            
            # Prepare output buffer
            output_buffer = bytearray(65536)  # 64KB buffer
            output_size = len(output_buffer)
            
            # Call jetstream_application
            jetstream_application(path, query_strings, self.command, http_params,
                                input_buffer, input_size, output_buffer, output_size)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.end_headers()
            
            # Find the actual content length in output_buffer (up to first null byte)
            try:
                actual_length = output_buffer.index(0)
            except ValueError:
                actual_length = len(output_buffer)
            
            self.wfile.write(output_buffer[:actual_length])
            
        except Exception as e:
            self.send_error(500, f"Internal Server Error: {str(e)}")
    
    def do_GET(self) -> None:
        """Handle GET requests"""
        self._handle_request()
    
    def do_POST(self) -> None:
        """Handle POST requests"""
        self._handle_request()
    
    def do_PUT(self) -> None:
        """Handle PUT requests"""
        self._handle_request()
    
    def do_DELETE(self) -> None:
        """Handle DELETE requests"""
        self._handle_request()
    
    def do_PATCH(self) -> None:
        """Handle PATCH requests"""
        self._handle_request()
    
    def log_message(self, format: str, *args: Any) -> None:
        """Override to customize logging"""
        print(f"[{self.address_string()}] {format % args}")


def jetstream_server() -> None:
    """Main server function that handles TLS/HTTP connections"""
    # Check for TLS certificates
    tls_key_path = "/etc/ssl/jetstream.key"
    tls_cert_path = "/etc/ssl/jetstream.crt"
    
    use_tls = os.path.exists(tls_key_path) and os.path.exists(tls_cert_path)
    port = 443 if use_tls else 7777
    
    print(f"Starting JetStream server on port {port}")
    print(f"TLS enabled: {use_tls}")
    
    # Create HTTP server
    server = HTTPServer(('0.0.0.0', port), JetStreamHandler)
    
    # Configure TLS if certificates exist
    if use_tls:
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(tls_cert_path, tls_key_path)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            print("TLS configured successfully")
        except Exception as e:
            print(f"Failed to configure TLS: {e}")
            print("Falling back to HTTP on port 7777")
            server.server_close()
            server = HTTPServer(('0.0.0.0', 7777), JetStreamHandler)
    
    print(f"JetStream server listening on {'https' if use_tls else 'http'}://0.0.0.0:{server.server_port}")

    # Start watchdog thread
    def _watchdog_loop():
        while True:
            try:
                now = time.time()
                if os.path.isdir(DATA):
                    with os.scandir(DATA) as it:
                        for entry in it:
                            try:
                                if not entry.is_file(follow_symlinks=False):
                                    continue
                                st = entry.stat(follow_symlinks=False)
                                # Delete if older than TTL
                                if now - st.st_mtime > WATCHDOG_TTL_SECONDS:
                                    os.remove(entry.path)
                            except FileNotFoundError:
                                continue
                            except Exception:
                                # Ignore watchdog errors for robustness
                                continue
            except Exception:
                pass
            time.sleep(WATCHDOG_TTL_SECONDS)

    threading.Thread(target=_watchdog_loop, name="jetstream_watchdog", daemon=True).start()
    
    try:
        # Handle multiple connections simultaneously using threading
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down JetStream server...")
        server.server_close()


if __name__ == "__main__":
    jetstream_server()