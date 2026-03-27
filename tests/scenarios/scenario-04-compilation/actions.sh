#!/usr/bin/env bash
# Action 1: Write source code
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d '{"command":"write /tmp/hello.c"}'
sudo docker exec "$CONTAINER" sh -c 'cat > /tmp/hello.c << EOF
#include <stdio.h>
#include <stdlib.h>
int main() {
    FILE *f = fopen("/tmp/output.txt", "w");
    fprintf(f, "compiled and running\n");
    fclose(f);
    system("cat /etc/hostname");
    return 0;
}
EOF'
sleep 1
curl -s -X POST "$URL/containers/$CID/actions/1/end" > /dev/null

# Action 2: Compile
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d '{"command":"gcc -o /tmp/hello /tmp/hello.c"}'
sudo docker exec "$CONTAINER" sh -c 'gcc -o /tmp/hello /tmp/hello.c'
sleep 2
curl -s -X POST "$URL/containers/$CID/actions/2/end" > /dev/null

# Action 3: Execute compiled binary
curl -s -X POST "$URL/containers/$CID/actions" \
    -H 'Content-Type: application/json' \
    -d '{"command":"/tmp/hello"}'
sudo docker exec "$CONTAINER" sh -c '/tmp/hello && cat /tmp/output.txt'
sleep 2
curl -s -X POST "$URL/containers/$CID/actions/3/end" > /dev/null
