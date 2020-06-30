import posix, libnetfilter_queue, libnetfilter_queue/[raw, utils]


proc cb(id: uint32, buffer: pointer, bufLen: int32, res: var Result) =
  if buffer == nil:
    return

  let
    pb = pktb_alloc(AF_INET, buffer, bufLen.csize_t, 0)
    ip = nfq_ip_get_hdr(pb)
  echo "got connection from: ", inet_ntoa(ip.srcaddr)
  if ip.protocol == 6:
    if  nfq_ip_set_transport_header(pb, ip) == 0:
      let tcp = nfq_tcp_get_hdr(pb)
      echo tcp[]
  #hexdump(cast[cstring](buffer), bufLen)
  # accept the packet and reinject it back to kernel
  pktb_free(pb)
  res.verdict = NF_ACCEPT

var nfq: NetfilterQueue

setControlCHook(proc() {.noconv.} =
  echo "Ctrl+C pressed, exiting.."
  nfq.close()
)

nfq = initNetfilterQueue(20, cb)
nfq.run()