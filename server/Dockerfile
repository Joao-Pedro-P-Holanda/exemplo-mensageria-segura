# Use a minimal base image
FROM golang:1.25.5-trixie AS build-stage

WORKDIR /server

COPY go.mod go.sum ./

RUN go mod download

COPY . ./

RUN CGO_ENABLED=1 GOOS=linux go build -tags="fts5"  -o /api

FROM gcr.io/distroless/base-debian13 AS build-release-stage

WORKDIR / 

COPY --from=build-stage /api /api
COPY key.pem ./key.pem

EXPOSE 8080

USER nonroot:nonroot

CMD ["/api"]
