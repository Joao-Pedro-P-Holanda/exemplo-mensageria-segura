# Use a minimal base image
FROM golang:1.25.5-trixie AS build-stage

WORKDIR /server

# Copy go module files and vendor directory
COPY go.mod go.sum ./
COPY vendor ./vendor

# Copy source code
COPY *.go ./

# Build using vendored dependencies
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -o /api

FROM gcr.io/distroless/base-debian13 AS build-release-stage

WORKDIR / 

COPY --from=build-stage /api /api

EXPOSE 8080

USER nonroot:nonroot

CMD ["/api"]
