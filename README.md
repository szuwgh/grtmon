# villus

Observable toolset base on ebpf

Quick-Start
--------------
1. download `villus`
```bash
git clone https://github.com/szuwgh/villus.git
```
2. build `villus`
```bash
cargo build
```
3. Run
```bash
target/debug/villus
``` 
4、check log
```bash
cd /sys/kernel/tracing
cat trace_pipe
``` 



