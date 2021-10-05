FROM gcr.io/distroless/java AS java

FROM gcr.io/distroless/static-debian10

COPY --from=java /etc/ssl/certs/java/cacerts /etc/ssl/certs/java/cacerts

COPY ./bin/cacertificatescsidriver /cacertificatescsidriver
ENTRYPOINT ["/cacertificatescsidriver"]
