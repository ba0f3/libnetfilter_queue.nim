##  libnfqnetlink.h: Header file for the Netfilter Queue library.
##
##  (C) 2005 by Harald Welte <laforge@gnumonks.org>
##
##
##  Changelog :
##  	(2005/08/11)  added  parsing function (Eric Leblond <regit@inl.fr>)
##
##  This software may be used and distributed according to the terms
##  of the GNU General Public License, incorporated herein by reference.
##

{.passL: "-lnfnetlink -lnetfilter_queue".}

import posix, private/nfnetlink_queue
export nfnetlink_queue

type
  nfq_callback* = (proc(qh: ptr nfq_q_handle; nfmsg: ptr nfgenmsg; nfad: ptr nfq_data;
                     data: pointer): cint)

  nfnl_handle* {.bycopy.} = object
  nfnl_subsys_handle* {.bycopy.} = object
  nlif_handle* {.bycopy.} = object

  nfq_handle* {.bycopy.} = object
    nfnlh*: ptr nfnl_handle
    nfnlssh*: ptr nfnl_subsys_handle
    qh_list*: ptr nfq_q_handle

  nfq_q_handle* {.bycopy.} = object
    next*: ptr nfq_q_handle
    h*: ptr nfq_handle
    id*: uint16
    cb*: nfq_callback
    data*: pointer

  nfq_data* {.bycopy.} = object
    data*: ptr ptr nfattr

  nlattr* {.bycopy.} = object
    nla_len*: uint16
    nla_type*: uint16

  pkt_buff* {.bycopy.} = object
  tcphdr* {.bycopy.} = object
  udphdr* {.bycopy.} = object
  iphdr* {.bycopy.} = object
  ip6_hdr* {.bycopy.} = object

const
  NF_DROP* = 0
  NF_ACCEPT* = 1
  NF_STOLEN* = 2
  NF_QUEUE* = 3
  NF_REPEAT* = 4
  NF_STOP* = 5
  NF_MAX_VERDICT* = NF_STOP

  NFQ_XML_HW* = (1 shl 0)
  NFQ_XML_MARK* = (1 shl 1)
  NFQ_XML_DEV* = (1 shl 2)
  NFQ_XML_PHYSDEV* = (1 shl 3)
  NFQ_XML_PAYLOAD* = (1 shl 4)
  NFQ_XML_TIME* = (1 shl 5)
  NFQ_XML_UID* = (1 shl 6)
  NFQ_XML_GID* = (1 shl 7)
  NFQ_XML_SECCTX* = (1 shl 8)
  NFQ_XML_ALL* = not 0

#var nfq_errno*: cint
{.push importc.}

proc nfq_nfnlh*(h: ptr nfq_handle): ptr nfnl_handle
proc nfq_fd*(h: ptr nfq_handle): cint

proc nfq_open*(): ptr nfq_handle
proc nfq_open_nfnl*(nfnlh: ptr nfnl_handle): ptr nfq_handle
proc nfq_close*(h: ptr nfq_handle): cint
proc nfq_bind_pf*(h: ptr nfq_handle; pf: uint16): cint
proc nfq_unbind_pf*(h: ptr nfq_handle; pf: uint16): cint
proc nfq_create_queue*(h: ptr nfq_handle; num: uint16; cb: nfq_callback;
                      data: pointer): ptr nfq_q_handle
proc nfq_destroy_queue*(qh: ptr nfq_q_handle): cint
proc nfq_handle_packet*(h: ptr nfq_handle; buf: cstring; len: cint): cint
proc nfq_set_mode*(qh: ptr nfq_q_handle; mode: uint8; len: cuint): cint
proc nfq_set_queue_maxlen*(qh: ptr nfq_q_handle; queuelen: uint32): cint
proc nfq_set_queue_flags*(qh: ptr nfq_q_handle; mask: uint32; flags: uint32): cint
proc nfq_set_verdict*(qh: ptr nfq_q_handle; id: uint32; verdict: uint32;
                     data_len: uint32; buf: ptr cuchar): cint
proc nfq_set_verdict2*(qh: ptr nfq_q_handle; id: uint32; verdict: uint32;
                      mark: uint32; datalen: uint32; buf: ptr cuchar): cint
proc nfq_set_verdict_batch*(qh: ptr nfq_q_handle; id: uint32; verdict: uint32): cint
proc nfq_set_verdict_batch2*(qh: ptr nfq_q_handle; id: uint32; verdict: uint32;
                            mark: uint32): cint
proc nfq_set_verdict_mark*(qh: ptr nfq_q_handle; id: uint32; verdict: uint32;
                          mark: uint32; datalen: uint32; buf: ptr cuchar): cint {.deprecated.}
##  message parsing function

proc nfq_get_msg_packet_hdr*(nfad: ptr nfq_data): ptr nfqnl_msg_packet_hdr
proc nfq_get_nfmark*(nfad: ptr nfq_data): uint32
proc nfq_get_timestamp*(nfad: ptr nfq_data; tv: ptr Timeval): cint
##  return 0 if not set

proc nfq_get_indev*(nfad: ptr nfq_data): uint32
proc nfq_get_physindev*(nfad: ptr nfq_data): uint32
proc nfq_get_outdev*(nfad: ptr nfq_data): uint32
proc nfq_get_physoutdev*(nfad: ptr nfq_data): uint32
proc nfq_get_uid*(nfad: ptr nfq_data; uid: ptr uint32): cint
proc nfq_get_gid*(nfad: ptr nfq_data; gid: ptr uint32): cint
proc nfq_get_secctx*(nfad: ptr nfq_data; secdata: ptr ptr cuchar): cint
proc nfq_get_indev_name*(nlif_handle: ptr nlif_handle; nfad: ptr nfq_data;
                        name: cstring): cint
proc nfq_get_physindev_name*(nlif_handle: ptr nlif_handle; nfad: ptr nfq_data;
                            name: cstring): cint
proc nfq_get_outdev_name*(nlif_handle: ptr nlif_handle; nfad: ptr nfq_data;
                         name: cstring): cint
proc nfq_get_physoutdev_name*(nlif_handle: ptr nlif_handle; nfad: ptr nfq_data;
                             name: cstring): cint
proc nfq_get_packet_hw*(nfad: ptr nfq_data): ptr nfqnl_msg_packet_hw
##  return -1 if problem, length otherwise

proc nfq_get_payload*(nfad: ptr nfq_data; data: ptr ptr cuchar): cint

proc nfq_snprintf_xml*(buf: cstring; len: csize_t; tb: ptr nfq_data; flags: cint): cint
##
##  New API based on libmnl
##

proc nfq_nlmsg_cfg_put_cmd*(nlh: ptr nlmsghdr; pf: uint16; cmd: uint8)
proc nfq_nlmsg_cfg_put_params*(nlh: ptr nlmsghdr; mode: uint8; range: cint)
proc nfq_nlmsg_cfg_put_qmaxlen*(nlh: ptr nlmsghdr; qmaxlen: uint32)
proc nfq_nlmsg_verdict_put*(nlh: ptr nlmsghdr; id: cint; verdict: cint)
proc nfq_nlmsg_verdict_put_mark*(nlh: ptr nlmsghdr; mark: uint32)
proc nfq_nlmsg_verdict_put_pkt*(nlh: ptr nlmsghdr; pkt: pointer; pktlen: uint32)
proc nfq_nlmsg_parse*(nlh: ptr nlmsghdr; pkt: ptr ptr nlattr): cint

proc nfq_ip_get_hdr*(pktb: ptr pkt_buff): ptr iphdr
proc nfq_ip_set_transport_header*(pktb: ptr pkt_buff; iph: ptr iphdr): cint
proc nfq_ip_set_checksum*(iph: ptr iphdr)
proc nfq_ip_mangle*(pkt: ptr pkt_buff; dataoff: cuint; match_offset: cuint;
                   match_len: cuint; rep_buffer: cstring; rep_len: cuint): cint
proc nfq_ip_snprintf*(buf: cstring; size: csize_t; iph: ptr iphdr): cint

proc nfq_ip6_get_hdr*(pktb: ptr pkt_buff): ptr ip6_hdr
proc nfq_ip6_set_transport_header*(pktb: ptr pkt_buff; iph: ptr ip6_hdr;
                                  target: uint8): cint
proc nfq_ip6_snprintf*(buf: cstring; size: csize_t; ip6h: ptr ip6_hdr): cint

proc nfq_tcp_get_hdr*(pktb: ptr pkt_buff): ptr tcphdr
proc nfq_tcp_get_payload*(tcph: ptr tcphdr; pktb: ptr pkt_buff): pointer
proc nfq_tcp_get_payload_len*(tcph: ptr tcphdr; pktb: ptr pkt_buff): cuint

proc nfq_tcp_compute_checksum_ipv4*(tcph: ptr tcphdr; iph: ptr iphdr)
proc nfq_tcp_compute_checksum_ipv6*(tcph: ptr tcphdr; ip6h: ptr ip6_hdr)
proc nfq_tcp_mangle_ipv4*(pkt: ptr pkt_buff; match_offset: cuint; match_len: cuint;
                         rep_buffer: cstring; rep_len: cuint): cint
proc nfq_tcp_snprintf*(buf: cstring; size: csize_t; tcp: ptr tcphdr): cint

proc nfq_udp_get_hdr*(pktb: ptr pkt_buff): ptr udphdr
proc nfq_udp_get_payload*(udph: ptr udphdr; pktb: ptr pkt_buff): pointer
proc nfq_udp_get_payload_len*(udph: ptr udphdr; pktb: ptr pkt_buff): cuint
proc nfq_udp_compute_checksum_ipv4*(udph: ptr udphdr; iph: ptr iphdr)
proc nfq_udp_compute_checksum_ipv6*(udph: ptr udphdr; ip6h: ptr ip6_hdr)
proc nfq_udp_mangle_ipv4*(pkt: ptr pkt_buff; match_offset: cuint; match_len: cuint;
                         rep_buffer: cstring; rep_len: cuint): cint
proc nfq_udp_snprintf*(buf: cstring; size: csize_t; udp: ptr udphdr): cint

{.pop.}