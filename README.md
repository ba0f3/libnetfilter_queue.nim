# libnetfilter_queue.nim
This is a high level wrapper of [libnetfilter_queue](https://netfilter.org/projects/libnetfilter_queue), for low level C api access please import `libnetfilter_queue/raw` instead, and checkout libnetfilter_queue's [documents](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/index.html) for more details


This module helps you build your own custom firewall with libnetfilter_queue library.

Currently it does not support multithreading nor async processing yet. To improve performance, consider use iptables's `--queue-balance` flags and start multiple instances that listen on multiple queues

## Installation
*`libnetfilter_queue1` is required, `libnetfilter-queue-dev` and `libmnl-dev` only required for development*

```shell
# Install libnetfilter-queue1 and its development headers
$ apt install libnetfilter-queue1 libnetfilter-queue-dev libmnl-dev

# Install this wrapper from Nimble directory
$ nimble intall libnetfilter_queue

```

## Usage
Route all imcoming traffic to NFQUEUE with your queue id (eg: 30)
```shell
$ iptables -t filter -A INPUT -j NFQUEUE --queue-num 30
```

Create a simple application to listen on queue id 30

```nim
import libnetfilter_queue, libnetfilter_queue/utils

proc cb(id: uint32, buffer: pointer, bufLen: int32, res: var Result) =
  echo "got packet id=", id, " with data size=", bufLen
  hexdump(cast[cstring](buffer), bufLen)
  # accept the packet and reinject it back to kernel
  res.verdict = NF_ACCEPT

var nfq: NetfilterQueue

setControlCHook(proc() {.noconv.} =
  echo "Ctrl+C pressed, exiting.."
  nfq.close()
)

nfq = initNetfilterQueue(20, cb)
nfq.run()
```

To stop routing traffic:
```shell
$ iptables -t filter -D INPUT -j NFQUEUE --queue-num 30
```
