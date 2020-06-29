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