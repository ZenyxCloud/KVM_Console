FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/kvm-console .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/kvm-console /kvm-console
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["/kvm-console", "-healthcheck"]
ENTRYPOINT ["/kvm-console"]
