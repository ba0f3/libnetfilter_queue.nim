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

import posix, ../private/nfnetlink_queue
export nfnetlink_queue

type
  nfq_callback = (proc(qh: nfq_q_handle; nfmsg: ptr nfgenmsg; nfad: ptr nfq_data;
                     data: pointer): int32 {.cdecl.})

  nfnl_handle* {.bycopy.} = object
  nfnl_subsys_handle* {.bycopy.} = object
  nlif_handle* {.bycopy.} = object

  nfq_handle* = ptr object
    nfnlh*: ptr nfnl_handle
    nfnlssh*: ptr nfnl_subsys_handle
    qh_list*: nfq_q_handle

  nfq_q_handle* = ptr object
    next*: nfq_q_handle
    h*: nfq_handle
    id*: uint16
    cb*: nfq_callback
    data*: pointer

  nfq_data* {.bycopy.} = object
    data*: ptr ptr nfattr

  nlattr* {.bycopy.} = object
    nla_len*: uint16
    nla_type*: uint16

  pkt_buff* {.bycopy.} = ptr object
    mac_header*: ptr uint8
    network_header*: ptr uint8
    transport_header*: ptr uint8
    data*: ptr uint8
    len*: uint32
    data_len*: uint32
    mangled*: bool

  tcphdr* {.bycopy, packed.} = ptr object
    srcport*: uint16
    dstport*: uint16
    seq*: uint32
    ack_seq*: uint32
    data_offset*: uint8      ##  4 bits
    fin* {.bitsize: 1.}: uint8
    syn* {.bitsize: 1.}: uint8
    rst* {.bitsize: 1.}: uint8
    psh* {.bitsize: 1.}: uint8
    ack* {.bitsize: 1.}: uint8
    urg* {.bitsize: 1.}: uint8
    ece* {.bitsize: 1.}: uint8
    cwr* {.bitsize: 1.}: uint8
    win*: uint16
    chksum*: uint16
    urgent*: uint16

  udphdr* {.bycopy.} = ptr object
    src_port*: uint16
    dst_port*: uint16
    length*: uint16
    checksum*: uint16

  iphdr* {.bycopy.} = ptr object
    ver_ihl*: uint8          ##  4 bits version and 4 bits internet header length
    tos*: uint8
    total_length*: uint16
    id*: uint16
    flags_fo*: uint16        ##  3 bits flags and 13 bits fragment-offset
    ttl*: uint8
    protocol*: uint8
    checksum*: uint16
    srcaddr*: InAddr
    dstaddr*: InAddr

  ip6hdr* {.bycopy.} = ptr object
    version* {.bitsize: 4.}: cuint
    traffic_class* {.bitsize: 8.}: cuint
    flow_label* {.bitsize: 20.}: cuint
    length*: uint16
    next_header*: uint8
    hop_limit*: uint8
    src*: In6Addr
    dst*: In6Addr


const
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

#var nfq_errno*: int32
{.push importc, cdecl, discardable.}

proc nfq_nfnlh*(h: nfq_handle): ptr nfnl_handle
proc nfq_fd*(h: nfq_handle): int32

proc nfq_open*(): nfq_handle
proc nfq_open_nfnl*(nfnlh: ptr nfnl_handle): nfq_handle
proc nfq_close*(h: nfq_handle): int32
proc nfq_bind_pf*(h: nfq_handle; pf: uint16): int32
proc nfq_unbind_pf*(h: nfq_handle; pf: uint16): int32
proc nfq_create_queue*(h: nfq_handle; num: uint16; cb: nfq_callback;
                      data: pointer): nfq_q_handle
proc nfq_destroy_queue*(qh: nfq_q_handle): int32
proc nfq_handle_packet*(h: nfq_handle; buf: cstring; len: int32): int32
proc nfq_set_mode*(qh: nfq_q_handle; mode: uint8; len: uint32): int32
proc nfq_set_queue_maxlen*(qh: nfq_q_handle; queuelen: uint32): int32
proc nfq_set_queue_flags*(qh: nfq_q_handle; mask: uint32; flags: uint32): int32
proc nfq_set_verdict*(qh: nfq_q_handle; id: uint32; verdict: uint32;
                     data_len: uint32; buf: pointer): int32
proc nfq_set_verdict2*(qh: nfq_q_handle; id: uint32; verdict: uint32;
                      mark: uint32; datalen: uint32; buf: pointer): int32
proc nfq_set_verdict_batch*(qh: nfq_q_handle; id: uint32; verdict: uint32): int32
proc nfq_set_verdict_batch2*(qh: nfq_q_handle; id: uint32; verdict: uint32;
                            mark: uint32): int32
proc nfq_set_verdict_mark*(qh: nfq_q_handle; id: uint32; verdict: uint32;
                          mark: uint32; datalen: uint32; buf: pointer): int32 {.deprecated.}
##  message parsing function

proc nfq_get_msg_packet_hdr*(nfad: ptr nfq_data): ptr nfqnl_msg_packet_hdr
proc nfq_get_nfmark*(nfad: ptr nfq_data): uint32
proc nfq_get_timestamp*(nfad: ptr nfq_data; tv: ptr Timeval): int32
##  return 0 if not set

proc nfq_get_indev*(nfad: ptr nfq_data): uint32
proc nfq_get_physindev*(nfad: ptr nfq_data): uint32
proc nfq_get_outdev*(nfad: ptr nfq_data): uint32
proc nfq_get_physoutdev*(nfad: ptr nfq_data): uint32
proc nfq_get_uid*(nfad: ptr nfq_data; uid: ptr uint32): int32
proc nfq_get_gid*(nfad: ptr nfq_data; gid: ptr uint32): int32
proc nfq_get_secctx*(nfad: ptr nfq_data; secdata: ptr pointer): int32
proc nfq_get_indev_name*(nlif_handle: ptr nlif_handle; nfad: ptr nfq_data;
                        name: cstring): int32
proc nfq_get_physindev_name*(nlif_handle: ptr nlif_handle; nfad: ptr nfq_data;
                            name: cstring): int32
proc nfq_get_outdev_name*(nlif_handle: ptr nlif_handle; nfad: ptr nfq_data;
                         name: cstring): int32
proc nfq_get_physoutdev_name*(nlif_handle: ptr nlif_handle; nfad: ptr nfq_data;
                             name: cstring): int32
proc nfq_get_packet_hw*(nfad: ptr nfq_data): ptr nfqnl_msg_packet_hw
##  return -1 if problem, length otherwise

proc nfq_get_payload*(nfad: ptr nfq_data; data: ptr pointer): int32

proc nfq_snprintf_xml*(buf: cstring; len: csize_t; tb: ptr nfq_data; flags: int32): int32
##
##  New API based on libmnl
##

proc nfq_nlmsg_cfg_put_cmd*(nlh: ptr nlmsghdr; pf: uint16; cmd: uint8)
proc nfq_nlmsg_cfg_put_params*(nlh: ptr nlmsghdr; mode: uint8; range: int32)
proc nfq_nlmsg_cfg_put_qmaxlen*(nlh: ptr nlmsghdr; qmaxlen: uint32)
proc nfq_nlmsg_verdict_put*(nlh: ptr nlmsghdr; id: int32; verdict: int32)
proc nfq_nlmsg_verdict_put_mark*(nlh: ptr nlmsghdr; mark: uint32)
proc nfq_nlmsg_verdict_put_pkt*(nlh: ptr nlmsghdr; pkt: pointer; pktlen: uint32)
proc nfq_nlmsg_parse*(nlh: ptr nlmsghdr; pkt: ptr ptr nlattr): int32

#[ Packet buffer ]#
proc pktb_alloc*(family: int32; data: pointer; len: csize_t; extra: csize_t): pkt_buff
proc pktb_free*(pktb: pkt_buff)
proc pktb_data*(pktb: pkt_buff): ptr uint8
proc pktb_len*(pktb: pkt_buff): uint32
proc pktb_push*(pktb: pkt_buff; len: uint32)
proc pktb_pull*(pktb: pkt_buff; len: uint32)
proc pktb_put*(pktb: pkt_buff; len: uint32)
proc pktb_trim*(pktb: pkt_buff; len: uint32)
proc pktb_tailroom*(pktb: pkt_buff): uint32
proc pktb_mac_header*(pktb: pkt_buff): ptr uint8
proc pktb_network_header*(pktb: pkt_buff): ptr uint8
proc pktb_transport_header*(pktb: pkt_buff): ptr uint8
proc pktb_mangle*(pktb: pkt_buff; dataoff: int32; match_offset: uint32;
                 match_len: uint32; rep_buffer: cstring; rep_len: uint32): int32
proc pktb_mangled*(pktb: pkt_buff): bool

#[ IPv4 helpers ]#
proc nfq_ip_get_hdr*(pktb: pkt_buff): iphdr
proc nfq_ip_set_transport_header*(pktb: pkt_buff; iph: iphdr): int32
proc nfq_ip_set_checksum*(iph: iphdr)
proc nfq_ip_mangle*(pkt: pkt_buff; dataoff: uint32; match_offset: uint32;
                   match_len: uint32; rep_buffer: cstring; rep_len: uint32): int32
proc nfq_ip_snprintf*(buf: cstring; size: csize_t; iph: iphdr): int32

#[ IPv6 helpers ]#
proc nfq_ip6_get_hdr*(pktb: pkt_buff): ip6hdr
proc nfq_ip6_set_transport_header*(pktb: pkt_buff; iph: ip6hdr;
                                  target: uint8): int32
proc nfq_ip6_snprintf*(buf: cstring; size: csize_t; ip6h: ip6hdr): int32

#[ TCP helpers ]#
proc nfq_tcp_get_hdr*(pktb: pkt_buff): tcphdr
proc nfq_tcp_get_payload*(tcph: tcphdr; pktb: pkt_buff): pointer
proc nfq_tcp_get_payload_len*(tcph: tcphdr; pktb: pkt_buff): uint32

proc nfq_tcp_compute_checksum_ipv4*(tcph: tcphdr; iph: iphdr)
proc nfq_tcp_compute_checksum_ipv6*(tcph: tcphdr; ip6h: ip6hdr)
proc nfq_tcp_mangle_ipv4*(pkt: pkt_buff; match_offset: uint32; match_len: uint32;
                         rep_buffer: cstring; rep_len: uint32): int32
proc nfq_tcp_snprintf*(buf: cstring; size: csize_t; tcp: tcphdr): int32

#[ UDP helpers ]#
proc nfq_udp_get_hdr*(pktb: pkt_buff): udphdr
proc nfq_udp_get_payload*(udph: udphdr; pktb: pkt_buff): pointer
proc nfq_udp_get_payload_len*(udph: udphdr; pktb: pkt_buff): uint32
proc nfq_udp_compute_checksum_ipv4*(udph: udphdr; iph: iphdr)
proc nfq_udp_compute_checksum_ipv6*(udph: udphdr; ip6h: ip6hdr)
proc nfq_udp_mangle_ipv4*(pkt: pkt_buff; match_offset: uint32; match_len: uint32;
                         rep_buffer: cstring; rep_len: uint32): int32
proc nfq_udp_snprintf*(buf: cstring; size: csize_t; udp: udphdr): int32

{.pop.}