# Rtmon
go runtime monitor based on ebpf

This is a command-line tool based on ebpf, which can observe the goroutine creation and running time of golang runtime, gc events and memory allocation distribution

##  User Guide

#### observe goroutine events
```
$ ./grtmon gr --binpath ./testgo/testgo
Tracing... Hit Ctrl-C to end.
   FN        GOID    PID     EVENT         TIME(ns)
   4d3160    0       0       create        0
   4d3160    41      0       exit          1000782659
   4d3100    0       0       create        0
   4d3100    42      0       exit          489692
   4d3160    0       0       create        0
   4d3160    51      0       exit          1001695123
   4d3100    0       0       create        0
   4d3100    43      0       exit          42666
   4d3160    0       0       create        0
   4d3160    44      0       exit          1000915666
   4d3100    0       0       create        0
   4d3100    52      0       exit          46576
```

#### observe goroutine latency distribution
```
$ ./grtmon gr seq --binpath ./testgo/testgo
Tracing... Hit Ctrl-C to end.
         latency(μs)    : count    distribution
         0 -> 1          : 0        |                                                            |
         2 -> 3          : 0        |                                                            |
         4 -> 7          : 4        |********                                                    |
         8 -> 15         : 1        |**                                                          |
        16 -> 31         : 5        |**********                                                  |
        32 -> 63         : 16       |**********************************                          |
        64 -> 127        : 4        |********                                                    |
       128 -> 255        : 3        |******                                                      |
       256 -> 511        : 28       |************************************************************|
       512 -> 1023       : 0        |                                                            |
      1024 -> 2047       : 0        |                                                            |
      2048 -> 4095       : 0        |                                                            |
      4096 -> 8191       : 0        |                                                            |
      8192 -> 16383      : 0        |                                                            |
     16384 -> 32767      : 0        |                                                            |
     32768 -> 65535      : 0        |                                                            |
     65536 -> 131071     : 0        |                                                            |
    131072 -> 262143     : 0        |                                                            |
    262144 -> 524287     : 0        |                                                            |
    524288 -> 1048575    : 28       |************************************************************|
```

#### observe gc event
```
$ ./grtmon gc --binpath ./testgo/testgo
Tracing... Hit Ctrl-C to end.
   EVENT         TIME(ns)
   stw           14230
   mark          576229
   sweep         4866
   stw           15189
   stw           201896
   mark          497816
   sweep         6262
   stw           12967
```

#### observe malloc memory distribution
```
$ ./grtmon gm --binpath ./testgo/testgo
Tracing... Hit Ctrl-C to end.
   malloc     : count    distribution
   < 16B      : 213      |******************************|
   24B        : 36       |*****                         |
   32B        : 126      |*****************             |
   48B        : 66       |*********                     |
   64B        : 23       |***                           |
   80B        : 17       |**                            |
   96B        : 38       |*****                         |
   112B       : 4        |                              |
   128B       : 2        |                              |
   144B       : 1        |                              |
   160B       : 11       |*                             |
   176B       : 0        |                              |
   192B       : 0        |                              |
   208B       : 23       |***                           |
   224B       : 0        |                              |
   240B       : 0        |                              |
   256B       : 19       |**                            |
   288B       : 2        |                              |
   320B       : 1        |                              |
   352B       : 5        |                              |
   384B       : 0        |                              |
   416B       : 54       |*******                       |
   448B       : 0        |                              |
   480B       : 1        |                              |
   512B       : 2        |                              |
   576B       : 3        |                              |
   640B       : 9        |*                             |
   704B       : 0        |                              |
   768B       : 0        |                              |
   896B       : 3        |                              |
   1024B      : 5        |                              |
   1152B      : 0        |                              |
   1280B      : 0        |                              |
   1408B      : 0        |                              |
   1536B      : 1        |                              |
   1792B      : 3        |                              |
   2048B      : 0        |                              |
   2304B      : 0        |                              |
   2688B      : 0        |                              |
   3072B      : 0        |                              |
   3200B      : 0        |                              |
   3456B      : 0        |                              |
   4096B      : 1        |                              |
   4864B      : 0        |                              |
   5376B      : 0        |                              |
   6144B      : 0        |                              |
   6528B      : 0        |                              |
   6784B      : 0        |                              |
   6912B      : 0        |                              |
   8192B      : 1        |                              |
   9472B      : 0        |                              |
   9728B      : 0        |                              |
   10240B     : 2        |                              |
   10880B     : 0        |                              |
   12288B     : 0        |                              |
   13568B     : 0        |                              |
   14336B     : 0        |                              |
   16384B     : 0        |                              |
   18432B     : 0        |                              |
   19072B     : 0        |                              |
   20480B     : 0        |                              |
   21760B     : 0        |                              |
   24576B     : 0        |                              |
   27264B     : 0        |                              |
   28672B     : 0        |                              |
   32768B     : 0        |                              |
   > 32K      : 1        |                              |
```


##  How to make

```
$ make build
cd user/ && go generate
Compiled /opt/goproject/rtmon/src/grtmon/user/bpf_bpfel_x86.o
Stripped /opt/goproject/rtmon/src/grtmon/user/bpf_bpfel_x86.o
Wrote /opt/goproject/rtmon/src/grtmon/user/bpf_bpfel_x86.go
cd testgo/ && go build
go build -v -o grtmon
```
