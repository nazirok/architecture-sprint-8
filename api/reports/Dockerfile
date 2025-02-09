# Build stage
FROM golang:1.22.0-alpine

WORKDIR /build
# Expose port
EXPOSE 8000

COPY . .

# Start nginx
CMD ["go", "run", "main.go"]