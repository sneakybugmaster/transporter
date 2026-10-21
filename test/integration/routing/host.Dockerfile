# syntax=docker/dockerfile:1
# Plain host behind the subnet router (see testhost/main.go).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/testhost ./test/integration/routing/testhost

FROM alpine:3.24
COPY --from=build /out/testhost /usr/local/bin/testhost
ENTRYPOINT ["/usr/local/bin/testhost"]
