all: backend_s3

backend_s3: backend_s3.go
	GOPATH=/usr/share/gocode GO111MODULE=off go build

clean:
	rm -f backend_s3
