# --- Stage 1: Build ---
FROM golang:1.24.0 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server
    
# --- Stage 2: Runtime ---
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /app/server /server
EXPOSE 80 
ENTRYPOINT ["/server"]
