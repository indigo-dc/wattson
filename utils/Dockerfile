FROM scratch
ADD wattson /
ADD ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/wattson"]
CMD ["--help"]