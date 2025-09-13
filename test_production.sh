#!/bin/bash

# Test script for JetstreamDB examples from README.md
# This script tests the basic functionality demonstrated in the JetstreamDB documentation
# Production version - tests on HTTPS port 443 with theme25.com host verification

set -e  # Exit on error

# Configuration
JETSTREAM_URL="https://theme25.com:443"
TEST_FILE="test_data.txt"
TEST_CONTENT="123"

# Cleanup function to run on exit
cleanup() {
    echo "Cleaning up..."
    rm -f "$TEST_FILE"
}
trap cleanup EXIT

# Function to check if Jetstream server is running
check_server() {
    if ! curl -s -k -o /dev/null --head --resolve "theme25.com:443:127.0.0.1" "$JETSTREAM_URL"; then
        echo "Error: Jetstream server is not running at $JETSTREAM_URL"
        echo "Please start the server before running tests."
        exit 1
    fi
}

# Function to run a test
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_exit_code=${3:-0}
    local expected_output="$4"
    
    echo "Running test: $test_name"
    echo "  Command: $command"
    
    set +e
    output=$(eval "$command" 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -ne $expected_exit_code ]; then
        echo "  ❌ Test failed: Expected exit code $expected_exit_code but got $exit_code"
        echo "  Output: $output"
        return 1
    fi
    
    if [ -n "$expected_output" ] && [ "$output" != "$expected_output" ]; then
        echo "  ❌ Test failed: Expected output containing '$expected_output' but got '$output'"
        return 1
    fi
    
    if [ -n "$expected_output" ]; then
        echo "  ✅ Test passed: Expected '$expected_output', got '$output'"
    else
        echo "  ✅ Test passed"
    fi
    return 0
}

# Main test function
run_tests() {
    echo "Starting JetstreamDB production tests..."
    
    # Check if server is running
    check_server
    
    # Test 1: Basic storage and retrieval
    run_test "Store content" "echo -n '$TEST_CONTENT' | curl -s -X PUT --data-binary @- --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL'" 0 "/a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3.dat"
    
    # Get the hash of the test content
    HASH=$(echo -n "$TEST_CONTENT" | sha256sum | cut -d' ' -f1)
    
    # Test 2: Retrieve stored content
    run_test "Retrieve stored content" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL/$HASH.dat'" 0 "$TEST_CONTENT"
    
    # Test 3: Try to delete content (should fail as it's read-only)
    run_test "Attempt to delete read-only content" "curl -s -X DELETE --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL/$HASH.dat'" 0
    
    # Verify content still exists
    run_test "Verify content still exists" "[ \"\$(curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL/$HASH.dat')\" = \"$TEST_CONTENT\" ]" 0
    
    # Test 4: Key-value store operations
    # Generate a random key
    KEY_HASH="13eabc1c70026450bedbc5e7647ab42f86042cc39aaa8df9e01a02907ede1003"
    
    # Test 5: Store key-value pair
    run_test "Store key-value pair" "echo -n 'value1' | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL/$KEY_HASH.dat?format=$JETSTREAM_URL*'" 0 "$JETSTREAM_URL/$KEY_HASH.dat"
    
    # Test 6: Retrieve key-value pair
    run_test "Retrieve key-value pair" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL/$KEY_HASH.dat'" 0 "value1"
    
    # Test 7: Update key-value pair
    run_test "Update key-value pair" "echo -n 'value2' | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL/$KEY_HASH.dat?format=$JETSTREAM_URL*'" 0 "$JETSTREAM_URL/$KEY_HASH.dat"
    
    # Test 8: Verify update
    run_test "Verify updated value" "[ \"\$(curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL/$KEY_HASH.dat')\" = \"value2\" ]" 0
    
    # Test 9: Delete key-value pair
    run_test "Delete key-value pair" "curl -s --resolve 'theme25.com:443:127.0.0.1' -X DELETE '$JETSTREAM_URL/$KEY_HASH.dat'" 0 "/$KEY_HASH.dat"
    
    # Test 10: Verify deletion returns empty response
    run_test "Verify deletion returns empty response" "[ \"\$(curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL/$KEY_HASH.dat')\" = \"\" ]" 0
    
    # Test 11: Burst functionality with SHA-256 hashes
    # Generate random SHA-256 hashes for filenames
    BURST_HASH1=$(echo "burst1" | sha256sum | cut -d' ' -f1)
    BURST_HASH2=$(echo "burst2" | sha256sum | cut -d' ' -f1)
    BURST_HASH3=$(echo "burst3" | sha256sum | cut -d' ' -f1)
    
    # Store three different files with SHA-256 hashed names
    run_test "Store burst file 1" "echo -n 'burst_content_1' | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL/$BURST_HASH1.dat'" 0 "/$BURST_HASH1.dat"
    run_test "Store burst file 2" "echo -n 'burst_content_2' | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL/$BURST_HASH2.dat'" 0 "/$BURST_HASH2.dat"
    run_test "Store burst file 3" "echo -n 'burst_content_3' | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL/$BURST_HASH3.dat'" 0 "/$BURST_HASH3.dat"
    
    # Create a file containing the paths to burst (newline separated)
    BURST_LIST="/tmp/burst_list_$(date +%s).txt"
    echo -e "/$BURST_HASH1.dat\n/$BURST_HASH2.dat\n/$BURST_HASH3.dat" > "$BURST_LIST"
    
    # Upload the file list to the server using PUT
    BURST_INDEX_HASH="98c28f9401ce161f3a3b3263fa6717fda3bad31fe685c82dbacab4b11cd077bd"
    run_test "Upload burst list file" "cat '$BURST_LIST' | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL/$BURST_INDEX_HASH.dat'" 0 "/$BURST_INDEX_HASH.dat"
    
    # Test burst without burst=1 (should return the list of files with newlines)
    run_test "Burst without parameter returns file list" "[ \"\$(curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL/$BURST_INDEX_HASH.dat')\" = \"$(cat "$BURST_LIST")\" ]" 0
    
    # Test burst with burst=1 (should return concatenated content)
    run_test "Burst with parameter returns concatenated content" "[ \"\$(curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL/$BURST_INDEX_HASH.dat?burst=1')\" = \"burst_content_1burst_content_2burst_content_3\" ]" 0
    
    # Clean up
    rm -f "$BURST_LIST"
    
    # Test 12: Synchronization - setifnot, append, and take operations
    SYNC_KEY="7574284e16a554088122dcd49e69f96061965d7c599f834393b563fb31854c7f"
    
    # Test setifnot=1 (should return path on success, empty string if file exists)
    run_test "Sync: setifnot first attempt should return path" "printf '123' | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL/$SYNC_KEY.dat?setifnot=1'" 0 "/$SYNC_KEY.dat"
    run_test "Sync: setifnot second attempt should return empty" "[ -z "$(echo 456 | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL/$SYNC_KEY.dat?setifnot=1')" ]" 0
    
    # Test append=1
    run_test "Sync: append to file" "printf ' line2' | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL/$SYNC_KEY.dat?append=1'" 0 "/$SYNC_KEY.dat"
    run_test "Sync: verify append" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL/$SYNC_KEY.dat'" 0 $'123 line2'
    
    # Test take=1 (should return content and delete)
    run_test "Sync: first take operation" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL/$SYNC_KEY.dat?take=1'" 0 $'123 line2'
    run_test "Sync: second take should return empty" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL/$SYNC_KEY.dat?take=1'" 0 ""
    
    # Test 13: Authorization - read-only blocks
    # Create a read-only block
    READONLY_CONTENT="This is a read-only block."
    READONLY_HASH=$(echo -n "$READONLY_CONTENT" | sha256sum | cut -d' ' -f1)
    
    # Create a mutable pointer to the read-only block
    MUTABLE_POINTER="971dc2a3b9c2774f7b6d4fbb72984bd1407ca6cc2e9e1b7c581f6aaf4199918c"
    
    # Store the read-only content (should succeed)
    run_test "Auth: store read-only block" "echo -n '$READONLY_CONTENT' | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL/$READONLY_HASH.dat'" 0 "/$READONLY_HASH.dat"
    
    # Create a mutable pointer to the read-only block
    run_test "Auth: create mutable pointer" "echo -n '/$READONLY_HASH.dat' | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL/$MUTABLE_POINTER.dat'" 0 "/$MUTABLE_POINTER.dat"
    
    # Verify the pointer works with burst=1
    run_test "Auth: verify pointer with burst=1" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL/$MUTABLE_POINTER.dat?burst=1'" 0 'This is a read-only block.'
    
    # Try to modify the read-only block (should fail)
    run_test "Auth: attempt to modify read-only block" "[ \"$(echo 'Modified content' | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL/$READONLY_HASH.dat')\" = '' ]" 0
    
    # Verify the read-only block is unchanged
    run_test "Auth: verify read-only block unchanged" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL/$READONLY_HASH.dat'" 0 'This is a read-only block.'
    
    # Cleanup test files
    # Test channel write functionality
    CHANNEL_PATH="/c8a0f4336661939fb8bd6ae796f11d7ff7ff5a48f8f66c57ddad6dc6a499223f.dat"
    TARGET_PATH="/34da034b42cba9f7001e131a62e9982248cd4011512a0bb900d6efad98dd4527.dat"
    CHANNEL_CONTENT="Write channel $TARGET_PATH"
    
    # Create the channel file
    run_test "Channel: create write channel" "curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT '$JETSTREAM_URL$CHANNEL_PATH' -d '$CHANNEL_CONTENT'" 0 "$CHANNEL_PATH"
    
    # Write "123" through the channel - should redirect to target
    run_test "Channel: write 123 through channel" "echo '123' | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL$CHANNEL_PATH'" 0 "$CHANNEL_PATH"
    
    # Read "123" from target file immediately after first write
    run_test "Channel: read 123 from target file" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL$TARGET_PATH'" 0 "123"
    
    # Read from channel file - should always return empty string
    run_test "Channel: read from channel returns empty (after 123)" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL$CHANNEL_PATH'" 0 ""
    
    # Write "456" through the channel - should redirect to target  
    run_test "Channel: write 456 through channel" "echo '456' | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL$CHANNEL_PATH'" 0 "$CHANNEL_PATH"
    
    # Read "456" from target file immediately after second write
    run_test "Channel: read 456 from target file" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL$TARGET_PATH'" 0 "456"
    
    # Read from channel file - should always return empty string
    run_test "Channel: read from channel returns empty (after 456)" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL$CHANNEL_PATH'" 0 ""
    
    # Test channel deletion protection - should fail to delete
    run_test "Channel: deletion protection" "[ \"\$(curl -s --resolve 'theme25.com:443:127.0.0.1' -X DELETE '$JETSTREAM_URL$CHANNEL_PATH')\" = '' ]" 0
    
    # Verify channel still exists after attempted deletion
    run_test "Channel: verify channel exists after failed delete" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL$CHANNEL_PATH'" 0 ""
    
    # Final test: verify data persistence after failed channel deletion
    run_test "Channel: read 456 from target file after failed delete" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL$TARGET_PATH'" 0 "456"

    # Test append channel functionality
    echo "Testing append channels..."
    
    APPEND_CHANNEL_PATH="/d9e1f2a3b4c5d6e7f8901234567890abcdef1234567890abcdef1234567890ab.dat"
    APPEND_TARGET_PATH="/f1e2d3c4b5a6978012345678901234567890abcdef1234567890abcdef123456.dat"
    APPEND_CHANNEL_CONTENT="Append channel $APPEND_TARGET_PATH"
    
    # Create the append channel file
    run_test "Append Channel: create append channel" "curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT '$JETSTREAM_URL$APPEND_CHANNEL_PATH' -d '$APPEND_CHANNEL_CONTENT'" 0 "$APPEND_CHANNEL_PATH"
    
    # Write "123" through the append channel - should redirect to target with append=1
    run_test "Append Channel: write 123 through channel" "printf '123' | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL$APPEND_CHANNEL_PATH'" 0 "$APPEND_CHANNEL_PATH"
    
    # Read "123" from target file immediately after first write
    run_test "Append Channel: read 123 from target file" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL$APPEND_TARGET_PATH'" 0 "123"
    
    # Read from append channel file - should always return empty string
    run_test "Append Channel: read from channel returns empty (after 123)" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL$APPEND_CHANNEL_PATH'" 0 ""
    
    # Write "456" through the append channel - should append to target  
    run_test "Append Channel: write 456 through channel" "printf '456' | curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT --data-binary @- '$JETSTREAM_URL$APPEND_CHANNEL_PATH'" 0 "$APPEND_CHANNEL_PATH"
    
    # Read "123456" from target file after append operation
    run_test "Append Channel: read 123456 from target file" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL$APPEND_TARGET_PATH'" 0 "123456"
    
    # Read from append channel file - should always return empty string
    run_test "Append Channel: read from channel returns empty (after 456)" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL$APPEND_CHANNEL_PATH'" 0 ""
    
    # Test append channel deletion protection - should fail to delete
    run_test "Append Channel: deletion protection" "[ \"\$(curl -s --resolve 'theme25.com:443:127.0.0.1' -X DELETE '$JETSTREAM_URL$APPEND_CHANNEL_PATH')\" = '' ]" 0
    
    # Verify append channel still exists after attempted deletion
    run_test "Append Channel: verify channel exists after failed delete" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL$APPEND_CHANNEL_PATH'" 0 ""
    
    # Final test: verify data persistence after failed append channel deletion
    run_test "Append Channel: read 123456 from target file after failed delete" "curl -s --resolve 'theme25.com:443:127.0.0.1' '$JETSTREAM_URL$APPEND_TARGET_PATH'" 0 "123456"

    echo "Cleaning up test files..."
    # Clean up specific test files mentioned by user
    rm -f /data/13eabc1c70026450bedbc5e7647ab42f86042cc39aaa8df9e01a02907ede1003.dat
    rm -f /data/a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd.dat
    rm -f /data/a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3.dat
    rm -f /data/c8a0f4336661939fb8bd6ae796f11d7ff7ff5a48f8f66c57ddad6dc6a499223f.dat
    rm -f /data/d9e1f2a3b4c5d6e7f8901234567890abcdef1234567890abcdef1234567890ab.dat
    
    # Clean up other test files
    rm -f /data/116c0596a6c5d34091de453c72d14d32034c99a1e299ee8a2509cac0484e70c8.dat
    rm -f /data/971dc2a3b9c2774f7b6d4fbb72984bd1407ca6cc2e9e1b7c581f6aaf4199918c.dat
    rm -f /data/98c28f9401ce161f3a3b3263fa6717fda3bad31fe685c82dbacab4b11cd077bd.dat
    rm -f /data/ab4355d74197337331deced720228224c0d4e752220cbb96eb070b6e7c3374fc.dat
    rm -f /data/e1e2e6d2718d543b1da0d2062f2d31add09953b0768e46d871df734e0becb5b5.dat
    rm -f /data/${CHANNEL_PATH#/}
    rm -f /data/${TARGET_PATH#/}
    rm -f /data/${APPEND_CHANNEL_PATH#/}
    rm -f /data/${APPEND_TARGET_PATH#/}
    
    # Read channel tests
    echo "Testing read channels..."
    
    CHANNEL_PATH="/a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd.dat"
    TARGET_PATH="/e1e2e6d2718d543b1da0d2062f2d31add09953b0768e46d871df734e0becb5b5.dat"
    
    # Test 1: Create a read channel
    run_test "Channel: create read channel" \
        "curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT \"$JETSTREAM_URL$CHANNEL_PATH\" -d 'Read channel $TARGET_PATH'" \
        0 "$CHANNEL_PATH"
    
    # Test 2: Write "123" to target file directly
    run_test "Channel: write 123 to target file" \
        "curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT \"$JETSTREAM_URL$TARGET_PATH\" -d '123'" \
        0 "$TARGET_PATH"
    
    # Test 3: Read through read channel (should get "123")
    run_test "Channel: read 123 through read channel" \
        "curl -s --resolve 'theme25.com:443:127.0.0.1' -X GET \"$JETSTREAM_URL$CHANNEL_PATH\"" \
        0 "123"
    
    # Test 4: Write "456" to target file directly
    run_test "Channel: write 456 to target file" \
        "curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT \"$JETSTREAM_URL$TARGET_PATH\" -d '456'" \
        0 "$TARGET_PATH"
    
    # Test 5: Read through read channel (should get "456")
    run_test "Channel: read 456 through read channel" \
        "curl -s --resolve 'theme25.com:443:127.0.0.1' -X GET \"$JETSTREAM_URL$CHANNEL_PATH\"" \
        0 "456"
    
    # Test 6: Try to write "789" to read channel (should fail)
    run_test "Channel: write to read channel should fail" \
        "curl -s --resolve 'theme25.com:443:127.0.0.1' -X PUT \"$JETSTREAM_URL$CHANNEL_PATH\" -d '789'" \
        0 ""
    
    # Test 7: Verify read channel still returns "456" after failed write
    run_test "Channel: read 456 from channel after failed write" \
        "curl -s --resolve 'theme25.com:443:127.0.0.1' -X GET \"$JETSTREAM_URL$CHANNEL_PATH\"" \
        0 "456"
    
    # Test 8: Try to delete read channel (should fail)
    run_test "Channel: delete read channel should fail" \
        "curl -s --resolve 'theme25.com:443:127.0.0.1' -X DELETE \"$JETSTREAM_URL$CHANNEL_PATH\"" \
        0 ""
    
    # Test 9: Verify read channel still exists and returns "456"
    run_test "Channel: read 456 from channel after failed delete" \
        "curl -s --resolve 'theme25.com:443:127.0.0.1' -X GET \"$JETSTREAM_URL$CHANNEL_PATH\"" \
        0 "456"
    
    # Test 10: Check volatile mode returns empty for read channel
    run_test "Channel: volatile mode returns empty for read channel" \
        "curl -s --resolve 'theme25.com:443:127.0.0.1' -X GET \"$JETSTREAM_URL$CHANNEL_PATH?volatile=1\"" \
        0 ""
    
    # Cleanup read channel test files
    rm -f /data/a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd.dat
    rm -f /data/e1e2e6d2718d543b1da0d2062f2d31add09953b0768e46d871df734e0becb5b5.dat
    
    echo "All tests completed successfully!"
}

# Run the tests
run_tests
