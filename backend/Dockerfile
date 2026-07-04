FROM golang:alpine AS build

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o aegix ./cmd/aegix

FROM alpine:latest
WORKDIR /app
COPY --from=build /app/aegix /usr/local/bin/aegix
EXPOSE 8000
CMD ["aegix"]
