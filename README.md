# libnetfilter_queue.nim
libnetfilter_queue wrapper for Nim

This module helps you build your own custom firewall with libnetfilter_queue library

## Installation
*libnetfilter_queue1 is required*

```shell
# Install libnetfilter-queue1 and its development headers
$ apt install libnetfilter-queue1 libnetfilter-queue-dev

# Install this wrapper from Nimble directory
$ nimble intall libnetfilter_queue

```

## Usage
Route all imcoming traffic to NFQUEUE with your queue id (eg: 30)
```shell
iptables -t filter -A INPUT -j NFQUEUE --queue-num 30
```

Create a simple application to listen on queue id 30

```nim
import posix, libnetfilter_queue

proc callback(qh: ptr nfq_q_handle; nfmsg: ptr nfgenmsg; nfa: ptr nfq_data; data: pointer): cint =
  let
    ph = nfq_get_msg_packet_hdr(nfa)
    id = ntohl(ph.packet_id.uint32)
  echo "hello from callback id=", id

  # accept packet and reinject it back to kernel
  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nil)

when isMainModule:
  var h = nfq_open()
  if h == nil:
    quit "error during nfq_open()"

  var qh = nfq_create_queue(h, 30, cb, nil)
  if qh == nil:
    quit("error during nfq_create_queue()")
  var
    fd = nfq_fd(h).SocketHandle
    buf: array[4096, char]
  while true:
    var rv = recv(fd, buf, sizeof(buf), 0).cint
    if rv >= 0:
      # packet received
      discard nfq_handle_packet(h, buf, rv)
  # unbinding from queue 30
  discard nfq_destroy_queue(qh)
  # closing library handle
  discard nfq_close(h)
````