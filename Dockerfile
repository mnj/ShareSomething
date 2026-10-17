# syntax=docker/dockerfile:1.7
# Multi-stage build: React app -> embedded into a static Rust binary -> distroless image.

FROM docker.io/library/node:22-alpine AS web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM docker.io/library/rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY backend ./backend
COPY --from=web /src/frontend/dist ./frontend/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && \
    install -D target/release/sharesomething /out/sharesomething && \
    mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sharesomething /usr/local/bin/sharesomething
COPY --from=build --chown=nonroot:nonroot /out/data /data
ENV SS_DATA_DIR=/data \
    SS_BIND=0.0.0.0:8080
VOLUME ["/data"]
EXPOSE 8080
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["/usr/local/bin/sharesomething", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/sharesomething"]
CMD ["serve"]
