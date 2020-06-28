import posix, libnetfilter_queue

proc cb(qh: ptr nfq_q_handle; nfmsg: ptr nfgenmsg; nfa: ptr nfq_data; data: pointer): cint =
  var
    id: uint32
    ph: ptr nfqnl_msg_packet_hdr

  ph = nfq_get_msg_packet_hdr(nfa)
  id = ntohl(ph.packet_id.uint32)
  echo "hello from callback id=", id
  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nil)

when isMainModule:
  var h = nfq_open()
  if h == nil:
    quit "error during nfq_open()"

  if nfq_unbind_pf(h, AF_INET.uint16) < 0:
    quit("error during nfq_unbind_pf()")

  if nfq_bind_pf(h, AF_INET.uint16) < 0:
    quit("error during nfq_bind_pf()")

  var
    qh: ptr nfq_q_handle
  qh = nfq_create_queue(h, 0, cb, nil)
  if qh == nil:
    quit("error during nfq_create_queue()")

  if nfq_set_mode(qh, 2, 0xffff) < 0:
    quit("can't set packet_copy mode")

  var fd = nfq_fd(h).SocketHandle
  var
    rv: cint
    buf = cast[cstring](alloc(4096))
  while true:
    rv = recv(fd, buf, 4096, 0).cint
    if rv < 0:
      break
    echo "pkt received"
    discard nfq_handle_packet(h, buf, rv)
  echo "unbinding from queue 0"
  discard nfq_destroy_queue(qh)
  echo "closing library handle"
  discard nfq_close(h)