# syntax=docker/dockerfile:1.7
# T-02 / T-08 / T-11 / T-15: multi-stage, distroless nonroot, no shell.
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/accounts-api .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/accounts-api /accounts-api
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/accounts-api"]
