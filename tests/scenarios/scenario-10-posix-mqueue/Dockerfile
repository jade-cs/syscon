FROM alpine:latest
RUN apk add --no-cache curl gcc musl-dev && mkdir -p /opt/tools

# POSIX mqueue sender
RUN printf '%s\n' \
  '#include <stdio.h>' \
  '#include <string.h>' \
  '#include <fcntl.h>' \
  '#include <sys/stat.h>' \
  '#include <mqueue.h>' \
  'int main(int argc, char *argv[]) {' \
  '    const char *file = argc > 1 ? argv[1] : "/etc/passwd";' \
  '    struct mq_attr attr = { .mq_maxmsg = 10, .mq_msgsize = 256 };' \
  '    mqd_t mq = mq_open("/covert", O_CREAT | O_WRONLY, 0600, &attr);' \
  '    if (mq == (mqd_t)-1) { perror("mq_open"); return 1; }' \
  '    FILE *fp = fopen(file, "r");' \
  '    if (!fp) { perror("fopen"); mq_close(mq); return 1; }' \
  '    char buf[256];' \
  '    while (fgets(buf, sizeof(buf), fp))' \
  '        mq_send(mq, buf, strlen(buf) + 1, 0);' \
  '    fclose(fp);' \
  '    buf[0] = 0; mq_send(mq, buf, 1, 0);' \
  '    mq_close(mq); return 0;' \
  '}' > /opt/tools/mq_sender.c && \
  gcc -o /opt/tools/mq_sender /opt/tools/mq_sender.c -lrt

# POSIX mqueue receiver
RUN printf '%s\n' \
  '#include <stdio.h>' \
  '#include <fcntl.h>' \
  '#include <mqueue.h>' \
  'int main(void) {' \
  '    mqd_t mq = mq_open("/covert", O_RDONLY);' \
  '    if (mq == (mqd_t)-1) { perror("mq_open"); return 1; }' \
  '    char buf[256]; unsigned int prio;' \
  '    while (1) {' \
  '        ssize_t n = mq_receive(mq, buf, sizeof(buf), &prio);' \
  '        if (n <= 0 || buf[0] == 0) break;' \
  '        printf("%s", buf);' \
  '    }' \
  '    mq_close(mq); mq_unlink("/covert"); return 0;' \
  '}' > /opt/tools/mq_receiver.c && \
  gcc -o /opt/tools/mq_receiver /opt/tools/mq_receiver.c -lrt

# socketpair relay
RUN printf '%s\n' \
  '#include <stdio.h>' \
  '#include <stdlib.h>' \
  '#include <string.h>' \
  '#include <unistd.h>' \
  '#include <sys/socket.h>' \
  '#include <sys/wait.h>' \
  'int main(int argc, char *argv[]) {' \
  '    const char *file = argc > 1 ? argv[1] : "/etc/passwd";' \
  '    int sv[2];' \
  '    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {' \
  '        perror("socketpair"); return 1; }' \
  '    pid_t pid = fork();' \
  '    if (pid < 0) { perror("fork"); return 1; }' \
  '    if (pid == 0) {' \
  '        close(sv[0]); char buf[512]; ssize_t n;' \
  '        while ((n = recv(sv[1], buf, sizeof(buf), 0)) > 0)' \
  '            write(STDOUT_FILENO, buf, n);' \
  '        close(sv[1]); _exit(0); }' \
  '    close(sv[1]);' \
  '    FILE *fp = fopen(file, "r");' \
  '    if (!fp) { perror("fopen"); return 1; }' \
  '    char buf[512]; size_t n;' \
  '    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)' \
  '        send(sv[0], buf, n, 0);' \
  '    fclose(fp); close(sv[0]); wait(NULL); return 0;' \
  '}' > /opt/tools/sockpair.c && \
  gcc -o /opt/tools/sockpair /opt/tools/sockpair.c
