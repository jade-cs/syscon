FROM alpine:latest
RUN apk add --no-cache curl gcc musl-dev && mkdir -p /opt/tools

# Sender: reads a file, sends line-by-line via SysV message queue
RUN printf '%s\n' \
  '#include <stdio.h>' \
  '#include <stdlib.h>' \
  '#include <string.h>' \
  '#include <sys/ipc.h>' \
  '#include <sys/msg.h>' \
  '/* Custom msgbuf — Alpine defines mtext[1] per POSIX */' \
  'struct mymsg { long mtype; char mtext[256]; };' \
  'int main(int argc, char *argv[]) {' \
  '    const char *file = argc > 1 ? argv[1] : "/etc/passwd";' \
  '    int msqid = msgget(0xCAFE, IPC_CREAT | 0600);' \
  '    if (msqid < 0) { perror("msgget"); return 1; }' \
  '    FILE *fp = fopen(file, "r");' \
  '    if (!fp) { perror("fopen"); return 1; }' \
  '    struct mymsg msg; msg.mtype = 1;' \
  '    while (fgets(msg.mtext, sizeof(msg.mtext), fp))' \
  '        msgsnd(msqid, &msg, strlen(msg.mtext) + 1, 0);' \
  '    fclose(fp);' \
  '    msg.mtext[0] = 0;' \
  '    msgsnd(msqid, &msg, 1, 0);' \
  '    return 0;' \
  '}' > /opt/tools/sender.c && \
  gcc -o /opt/tools/sender /opt/tools/sender.c

# Receiver: reads from SysV mqueue, writes to stdout
RUN printf '%s\n' \
  '#include <stdio.h>' \
  '#include <string.h>' \
  '#include <sys/ipc.h>' \
  '#include <sys/msg.h>' \
  'struct mymsg { long mtype; char mtext[256]; };' \
  'int main(void) {' \
  '    int msqid = msgget(0xCAFE, 0600);' \
  '    if (msqid < 0) { perror("msgget"); return 1; }' \
  '    struct mymsg msg;' \
  '    while (1) {' \
  '        if (msgrcv(msqid, &msg, sizeof(msg.mtext), 0, 0) < 0) break;' \
  '        if (msg.mtext[0] == 0) break;' \
  '        printf("%s", msg.mtext);' \
  '    }' \
  '    msgctl(msqid, IPC_RMID, NULL);' \
  '    return 0;' \
  '}' > /opt/tools/receiver.c && \
  gcc -o /opt/tools/receiver /opt/tools/receiver.c
