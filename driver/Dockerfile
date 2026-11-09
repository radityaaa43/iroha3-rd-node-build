# Runtime image for the rd-dfabi driver. The binary is built by driver/build.sh (capped
# container, upstream workspace @ 071e281e); this file only packages it.
FROM debian:bookworm-slim
RUN apt-get update -y && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1001 rd && useradd -u 1001 -g 1001 -M -s /usr/sbin/nologin rd
COPY dist/rd-dfabi /usr/local/bin/rd-dfabi
USER 1001:1001
ENTRYPOINT ["/usr/local/bin/rd-dfabi"]
