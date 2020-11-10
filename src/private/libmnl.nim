##
##  Netlink socket API
##
import posix, netlink, nfnetlink_queue, ../libnetfilter_queue/raw

const
  MNL_SOCKET_AUTOPID* = 0
  MNL_SOCKET_BUFFER_SIZE* = 8192

type
  mnl_socket* {.bycopy.} = ptr object

{.push importc, cdecl, discardable.}

proc mnl_socket_open*(bus: cint): mnl_socket
proc mnl_socket_open2*(bus: cint; flags: cint): mnl_socket
proc mnl_socket_fdopen*(fd: cint): mnl_socket
proc mnl_socket_bind*(nl: mnl_socket; groups: cuint; pid: Pid): cint
proc mnl_socket_close*(nl: mnl_socket): cint
proc mnl_socket_get_fd*(nl: mnl_socket): cint
proc mnl_socket_get_portid*(nl: mnl_socket): cuint
proc mnl_socket_sendto*(nl: mnl_socket; req: pointer; siz: csize_t): csize_t
proc mnl_socket_recvfrom*(nl: mnl_socket; buf: pointer; siz: csize_t): csize_t
proc mnl_socket_setsockopt*(nl: mnl_socket; `type`: cint; buf: pointer;
                           len: SockLen): cint
proc mnl_socket_getsockopt*(nl: mnl_socket; `type`: cint; buf: pointer;
                           len: ptr SockLen): cint
##
##  Netlink message API
##

const
  MNL_ALIGNTO* = 4

template MNL_ALIGN*(len: untyped): untyped =
  (((len) + MNL_ALIGNTO - 1) and not (MNL_ALIGNTO - 1))

const
  MNL_NLMSG_HDRLEN* = MNL_ALIGN(sizeof(nlmsghdr))

proc mnl_nlmsg_size*(len: csize_t): csize_t
proc mnl_nlmsg_get_payload_len*(nlh: ptr nlmsghdr): csize_t
##  Netlink message header builder

proc mnl_nlmsg_put_header*(buf: pointer): ptr nlmsghdr
proc mnl_nlmsg_put_extra_header*(nlh: ptr nlmsghdr; size: csize_t): pointer
##  Netlink message iterators

proc mnl_nlmsg_ok*(nlh: ptr nlmsghdr; len: cint): bool
proc mnl_nlmsg_next*(nlh: ptr nlmsghdr; len: ptr cint): ptr nlmsghdr
##  Netlink sequence tracking

proc mnl_nlmsg_seq_ok*(nlh: ptr nlmsghdr; seq: cuint): bool
##  Netlink portID checking

proc mnl_nlmsg_portid_ok*(nlh: ptr nlmsghdr; portid: cuint): bool
##  Netlink message getters

proc mnl_nlmsg_get_payload*(nlh: ptr nlmsghdr): pointer
proc mnl_nlmsg_get_payload_offset*(nlh: ptr nlmsghdr; offset: csize_t): pointer
proc mnl_nlmsg_get_payload_tail*(nlh: ptr nlmsghdr): pointer
##  Netlink message printer

proc mnl_nlmsg_fprintf*(fd: ptr FILE; data: pointer; datalen: csize_t;
                       extra_header_size: csize_t)
##  Message batch helpers

type
  mnl_nlmsg_batch* {.bycopy.} = object


proc mnl_nlmsg_batch_start*(buf: pointer; bufsiz: csize_t): ptr mnl_nlmsg_batch
proc mnl_nlmsg_batch_next*(b: ptr mnl_nlmsg_batch): bool
proc mnl_nlmsg_batch_stop*(b: ptr mnl_nlmsg_batch)
proc mnl_nlmsg_batch_size*(b: ptr mnl_nlmsg_batch): csize_t
proc mnl_nlmsg_batch_reset*(b: ptr mnl_nlmsg_batch)
proc mnl_nlmsg_batch_head*(b: ptr mnl_nlmsg_batch): pointer
proc mnl_nlmsg_batch_current*(b: ptr mnl_nlmsg_batch): pointer
proc mnl_nlmsg_batch_is_empty*(b: ptr mnl_nlmsg_batch): bool
##
##  Netlink attributes API
##

const
  MNL_ATTR_HDRLEN* = MNL_ALIGN(sizeof(nlattr))

##  TLV attribute getters

proc mnl_attr_get_type*(attr: ptr nlattr): uint16
proc mnl_attr_get_len*(attr: ptr nlattr): uint16
proc mnl_attr_get_payload_len*(attr: ptr nlattr): uint16
proc mnl_attr_get_payload*(attr: ptr nlattr): pointer
proc mnl_attr_get_u8*(attr: ptr nlattr): uint8
proc mnl_attr_get_u16*(attr: ptr nlattr): uint16
proc mnl_attr_get_u32*(attr: ptr nlattr): uint32
#proc mnl_attr_get_u64*(attr: ptr nlattr): uint64
proc mnl_attr_get_str*(attr: ptr nlattr): cstring
##  TLV attribute putters

proc mnl_attr_put*(nlh: ptr nlmsghdr; `type`: uint16; len: csize_t; data: pointer)
proc mnl_attr_put_u8*(nlh: ptr nlmsghdr; `type`: uint16; data: uint8)
proc mnl_attr_put_u16*(nlh: ptr nlmsghdr; `type`: uint16; data: uint16)
proc mnl_attr_put_u32*(nlh: ptr nlmsghdr; `type`: uint16; data: uint32)
proc mnl_attr_put_u64*(nlh: ptr nlmsghdr; `type`: uint16; data: uint64)
proc mnl_attr_put_str*(nlh: ptr nlmsghdr; `type`: uint16; data: cstring)
proc mnl_attr_put_strz*(nlh: ptr nlmsghdr; `type`: uint16; data: cstring)
##  TLV attribute putters with buffer boundary checkings

proc mnl_attr_put_check*(nlh: ptr nlmsghdr; buflen: csize_t; `type`: uint16; len: csize_t;
                        data: pointer): bool
proc mnl_attr_put_u8_check*(nlh: ptr nlmsghdr; buflen: csize_t; `type`: uint16;
                           data: uint8): bool
proc mnl_attr_put_u16_check*(nlh: ptr nlmsghdr; buflen: csize_t; `type`: uint16;
                            data: uint16): bool
proc mnl_attr_put_u32_check*(nlh: ptr nlmsghdr; buflen: csize_t; `type`: uint16;
                            data: uint32): bool
proc mnl_attr_put_u64_check*(nlh: ptr nlmsghdr; buflen: csize_t; `type`: uint16;
                            data: uint64): bool
proc mnl_attr_put_str_check*(nlh: ptr nlmsghdr; buflen: csize_t; `type`: uint16;
                            data: cstring): bool
proc mnl_attr_put_strz_check*(nlh: ptr nlmsghdr; buflen: csize_t; `type`: uint16;
                             data: cstring): bool
##  TLV attribute nesting

proc mnl_attr_nest_start*(nlh: ptr nlmsghdr; `type`: uint16): ptr nlattr
proc mnl_attr_nest_start_check*(nlh: ptr nlmsghdr; buflen: csize_t; `type`: uint16): ptr nlattr
proc mnl_attr_nest_end*(nlh: ptr nlmsghdr; start: ptr nlattr)
proc mnl_attr_nest_cancel*(nlh: ptr nlmsghdr; start: ptr nlattr)
##  TLV validation

proc mnl_attr_type_valid*(attr: ptr nlattr; maxtype: uint16): cint
type
  mnl_attr_data_type* = enum
    MNL_TYPE_UNSPEC, MNL_TYPE_U8, MNL_TYPE_U16, MNL_TYPE_U32, MNL_TYPE_U64,
    MNL_TYPE_STRING, MNL_TYPE_FLAG, MNL_TYPE_MSECS, MNL_TYPE_NESTED,
    MNL_TYPE_NESTED_COMPAT, MNL_TYPE_NUL_STRING, MNL_TYPE_BINARY, MNL_TYPE_MAX


proc mnl_attr_validate*(attr: ptr nlattr; `type`: mnl_attr_data_type): cint
proc mnl_attr_validate2*(attr: ptr nlattr; `type`: mnl_attr_data_type; len: csize_t): cint
##  TLV iterators

proc mnl_attr_ok*(attr: ptr nlattr; len: cint): bool
proc mnl_attr_next*(attr: ptr nlattr): ptr nlattr
##  TLV callback-based attribute parsers

type
  mnl_attr_cb_t* = proc (attr: ptr nlattr; data: pointer): cint

proc mnl_attr_parse*(nlh: ptr nlmsghdr; offset: cuint; cb: mnl_attr_cb_t; data: pointer): cint
proc mnl_attr_parse_nested*(attr: ptr nlattr; cb: mnl_attr_cb_t; data: pointer): cint
proc mnl_attr_parse_payload*(payload: pointer; payload_len: csize_t; cb: mnl_attr_cb_t;
                            data: pointer): cint
##
##  callback API
##

const
  MNL_CB_ERROR* = -1
  MNL_CB_STOP* = 0
  MNL_CB_OK* = 1

type
  mnl_cb_t* = proc (nlh: ptr nlmsghdr; data: pointer): cint

proc mnl_cb_run*(buf: pointer; numbytes: csize_t; seq: cuint; portid: cuint;
                cb_data: mnl_cb_t; data: pointer): cint
proc mnl_cb_run2*(buf: pointer; numbytes: csize_t; seq: cuint; portid: cuint;
                 cb_data: mnl_cb_t; data: pointer; cb_ctl_array: ptr mnl_cb_t;
                 cb_ctl_array_len: cuint): cint
##
##  other declarations
##

when not defined(MNL_ARRAY_SIZE):
  template MNL_ARRAY_SIZE*(a: untyped): untyped =
    (sizeof((a) div sizeof(((a)[0]))))

{.pop.}