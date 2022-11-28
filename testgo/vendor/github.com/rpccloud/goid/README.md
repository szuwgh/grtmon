# goid
[![Test](https://github.com/rpccloud/goid/workflows/Test/badge.svg)](https://github.com/rpccloud/goid/actions?query=workflow%3ATest)
[![Lint](https://github.com/rpccloud/goid/workflows/Lint/badge.svg)](https://github.com/rpccloud/goid/actions?query=workflow%3ALint)
[![codecov](https://codecov.io/gh/rpccloud/goid/branch/master/graph/badge.svg)](https://codecov.io/gh/rpccloud/goid)
[![Go Report Card](https://goreportcard.com/badge/github.com/rpccloud/goid)](https://goreportcard.com/report/github.com/rpccloud/goid)

An elegant way to get goroutine id

## Usage
```go
package main

import (
  "fmt"
  "github.com/rpccloud/goid"
)

func main() {
  fmt.Println("Current Goroutine ID:", goid.GetRoutineId())
}
```

## Benchmark
```bash
$ go test -bench=.
goos: darwin
goarch: amd64
pkg: github.com/rpccloud/goid
BenchmarkGetRoutineId-12         1000000000               0.413 ns/op           0 B/op          0 allocs/op
PASS
ok      github.com/rpccloud/goid        1.040s
```

