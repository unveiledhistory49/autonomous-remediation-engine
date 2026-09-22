.PHONY: all build test chaos clean

all: build

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/remediation-daemon ./cmd/remediation-daemon
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/remediation-ctl ./cmd/remediation-ctl
	@ln -sf remediation-ctl bin/autonomous-remediation-ctl
	@echo "Build complete. Artifacts located in bin/"

test:
	go test -v ./...

chaos: build
	./test/chaos/run_all_chaos.sh

clean:
	rm -rf bin/
	rm -f /tmp/remediation-*.wal /tmp/remediation-*.json /tmp/remediation.sock
	rm -rf /tmp/remediation-locks /tmp/remediation-journal /tmp/remediation-test-*
	@echo "Clean complete."
