# Start from the latest golang base image
FROM golang:latest

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
# COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
# RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
RUN git clone https://github.com/tluyben/smtp-rate-limiter.git

# Build the Go app
RUN cd smtp-rate-limiter && go mod download
RUN cd smtp-rate-limiter && make

# Expose port 25 to the outside world
EXPOSE 25

# Command to run the executable
CMD ["/app/smtp-rate-limiter/smtp-rate-limiter"]
