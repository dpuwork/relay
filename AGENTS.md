# OpenCode Agent Instructions

## Architecture & Entrypoints
- This is a high-performance zero-copy TCP relay system written in Go.
- Application entrypoints are in `cmd/`:
  - `cmd/relay`: The central relay server.
  - `cmd/agent`: The agent that connects local targets to the relay.
  - `cmd/demo`: An end-to-end integration test and demo.
- **Ignore the `main.go` file at the root**—it is merely a scratchpad.

## Core Constraint: Zero-Copy Splicing
- The Relay server achieves high throughput by using Linux kernel-space splicing (`splice(2)`).
- This relies on Go's `io.Copy` receiving raw `*net.TCPConn` objects via `protocol.UnwrapTCP`.
- **CRITICAL**: Do not wrap data-plane connections with interfaces like `bufio.Reader`, `bufio.Writer`, `io.LimitReader`, or `net.Pipe` in the relay core (e.g. `spliceConnections`) or in tests. Wrapping connections forces user-space memory copies, entirely breaking the zero-copy pipeline.

## Verification & Testing
- **Unit & Integration Tests**: Run `go test ./...`. The integration tests in `cmd/relay/relay_test.go` spin up real TCP loopback listeners to preserve splicing characteristics (mocking with `net.Pipe` breaks `UnwrapTCP`).
- **Zero-Copy Benchmark Validation**: Run `go test ./cmd/relay -bench . -benchmem`.
  - **Success Criteria**: You MUST see `0 allocs/op` in `BenchmarkRelayThroughput`. If allocations appear, the `splice(2)` pipeline is broken, and the system is quietly falling back to heavy userspace memory copying.

## Common Commands
- **Run demo**: `go run cmd/demo/main.go`
- **Run tests**: `go test ./...`
- **Run benchmarks**: `go test ./cmd/relay -bench . -benchmem`
- **Linting**: Standard `go fmt ./... && go vet ./...`
