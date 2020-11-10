import posix, libnetfilter_queue/raw, private/[libmnl, netlink]

const
  NF_DROP* = 0
  NF_ACCEPT* = 1
  NF_STOLEN* = 2
  NF_QUEUE* = 3
  NF_REPEAT* = 4
  NF_STOP* = 5
  NF_MAX_VERDICT* = NF_STOP


type
  NetfilterQueue* = object
    h: nfq_handle
    qh: nfq_q_handle
    fd: SocketHandle
    running*: bool

  Result* = object
    verdict*: uint32
    length*: uint32
    data*: pointer

  Callback = proc(id: uint32, buffer: pointer, bufLen: int32, vc: var Result) {.nimcall.}

template error(msg: string) = raise newException(IOError, msg)

proc nfq_callback(qh: nfq_q_handle; nfmsg: ptr nfgenmsg; nfa: ptr nfq_data; data: pointer): int32 {.cdecl.} =
  var
    ph = nfq_get_msg_packet_hdr(nfa)
    id = ntohl(ph.packet_id.uint32)
    cb = cast[Callback](data)
    buffer: pointer
    bufLen = nfq_get_payload(nfa, addr buffer).int32
    res: Result

  if cb == nil:
    echo "warn: callback not set, accept by default"
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nil)

  cb(id, buffer, bufLen, res)
  return nfq_set_verdict(qh, id, res.verdict, res.length, res.data)

proc initNetfilterQueue*(num: uint16, cb: Callback): NetfilterQueue =
  ## Register `cb` to NFQUEUE `num`

  var
    h: nfq_handle
    qh: nfq_q_handle
    fd: SocketHandle

  h = nfq_open()
  if h == nil:
    error("error during nfq_open()")

  if nfq_unbind_pf(h, AF_INET.uint16) < 0:
    nfq_close(h)
    error("error during nfq_unbind_pf() for AF_INET")

  if nfq_unbind_pf(h, AF_INET6.uint16) < 0:
    nfq_close(h)
    error("error during nfq_unbind_pf() for AF_INET6")

  if nfq_bind_pf(h, AF_INET.uint16) < 0:
    nfq_close(h)
    error("error during nfq_bind_pf() for AF_INET")

  if nfq_bind_pf(h, AF_INET6.uint16) < 0:
    nfq_close(h)
    error("error during nfq_bind_pf() for AF_INET6")

  qh = nfq_create_queue(h, num, nfq_callback, cb)
  if qh == nil:
    nfq_close(h)
    error "error during nfq_create_queue()"

  if nfq_set_mode(qh, 2, 0xffff) < 0:
    nfq_close(h)
    nfq_destroy_queue(qh)
    error "can't set packet_copy mode"
  fd = nfq_fd(h).SocketHandle

  NetfilterQueue(
    h: h,
    qh: qh,
    fd: fd
  )

proc run*(nfq: var NetfilterQueue) =
  ## Start main loop to recieve packets
  var
    buf = cast[cstring](alloc(4096))

  nfq.running = true
  while nfq.running:
    let rv = recv(nfq.fd, buf, 4096, 0).int32
    if rv >= 0:
      nfq_handle_packet(nfq.h, buf, rv)
  dealloc(buf)

proc close*(nfq: var NetfilterQueue) =
  ## Stop the loop, clean allocated resources
  nfq.running = false
  nfq_destroy_queue(nfq.qh)
  nfq_close(nfq.h)



#[
  https://git.netfilter.org/libnetfilter_queue/tree/examples/nf-queue.c
  var
    nl: mnl_socket
    buffer: pointer
    sizeofBuffer = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2)
    nhl: nlmsghdr
    portid: cuint

  nl = mnl_socket_open(NETLINK_NETFILTER)
  if nl == nil:
    error("mnl_socket_open")

  if mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0:
    error("mnl_socket_bind")

  portid = mnl_socket_get_portid(nl)
  buffer = alloc(sizeofBuffer)
  if buffer == nil:
    error("allocate receive buffer")

  nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, num)
]#