FROM alpine:latest
RUN apk add --no-cache curl
# Agent workspace with sensitive files
RUN echo "db_password=s3cr3t_pr0d_k3y" > /etc/app-secrets.conf
