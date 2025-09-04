all: backend_s3

backend_s3: backend_s3.go loggy.go hit_tracker.go slabqueue.go
	GOPATH=/usr/share/gocode GO111MODULE=off go build -ldflags "-s -w"

clean:
	rm -f backend_s3
