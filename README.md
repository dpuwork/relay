# Relay

A Layer 4 TCP relay written in Go.
It uses Linux `splice(2)` to move data directly within the kernel. 

## Commands

- **Demo:** `go run cmd/demo/main.go`
- **Test:** `go test ./...`
- **Benchmark:** `go test ./cmd/relay -bench . -benchmem`

## Performance

Load testing results on Apple M1 (darwin/arm64) using `go test ./cmd/relay -bench . -benchmem -count 5`:

```text
BenchmarkRelayThroughput-8        119581          8707 ns/op    3763.51 MB/s           0 B/op          0 allocs/op
BenchmarkRelayThroughput-8         93949         10994 ns/op    2980.58 MB/s           0 B/op          0 allocs/op
BenchmarkRelayThroughput-8        153513         10935 ns/op    2996.61 MB/s           0 B/op          0 allocs/op
BenchmarkRelayThroughput-8        120759         12914 ns/op    2537.45 MB/s           0 B/op          0 allocs/op
BenchmarkRelayThroughput-8        131126          9144 ns/op    3583.54 MB/s           0 B/op          0 allocs/op
```

Note: The `0 allocs/op` validates `splice(2)` hypothesis: no userspace memory allocations.
