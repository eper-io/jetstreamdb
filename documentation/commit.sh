#!/bin/bash
tigurl=$(head -n 1 .implementation/jetstreamdb.key.url 2>/dev/null || echo "https://null.theme25.com?apikey=secret")
echo "$tigurl"
(tail -n +1 ".implementation/commits.txt" | grep tig | xargs -n 1 -I {} bash -c "curl -X GET {} | head -c 20") >/dev/null
tar -cf - $(git ls-files --exclude-standard --cached --others) | curl -X 'PUT' --data-binary @- "${tigurl}&format=${tigurl//\?apikey=*/%25s?Content-Type=application/x-tar}" >>".implementation/commits.txt"
echo >>".implementation/commits.txt"
cat ".implementation/commits.txt"
exit

# This document is Licensed under Creative Commons CC0.
# To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights
# to this document to the public domain worldwide.
# This document is distributed without any warranty.
# You should have received a copy of the CC0 Public Domain Dedication along with this document.
# If not, see https://creativecommons.org/publicdomain/zero/1.0/legalcode.

# This script will commit the current codebase to a Jetstreamdb server. All you need to do is to run the file periodically to prevent auto deletion.
# Usage:
# 1. Make sure you have a Jetstreamdb server running.
# 2. Set the Jetstreamdb url with apikey in the file .implementation/jetstreamdb.key.url
# 3. Run this script periodically, e.g., via cron or manually.
# 4. bash ./documentation/commit.sh
