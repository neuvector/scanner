# This is a renovate-friendly source of Docker images.
FROM python:3.13.3-slim-bullseye@sha256:9e3f9243e06fd68eb9519074b49878eda20ad39a855fac51aaffb741de20726e AS python
FROM otel/weaver:v0.21.0@sha256:b144c94bbb8b09246f24d2b705636e177af8fd954f9f6756e7fb5663d6f86188 AS weaver
FROM avtodev/markdown-lint:v1@sha256:6aeedc2f49138ce7a1cd0adffc1b1c0321b841dc2102408967d9301c031949ee AS markdown
