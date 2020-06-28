type
  nfqnl_msg_types* = enum
    NFQNL_MSG_PACKET,         ##  packet from kernel to userspace
    NFQNL_MSG_VERDICT,        ##  verdict from userspace to kernel
    NFQNL_MSG_CONFIG,         ##  connect to a particular queue
    NFQNL_MSG_VERDICT_BATCH,  ##  batchv from userspace to kernel
    NFQNL_MSG_MAX

  nfattr* {.bycopy.} = object
    nfa_len*: uint16
    nfa_type*: uint16       ##  we use 15 bits for the type, and the highest
                       ##  bit to indicate whether the payload is nested

  nfgenmsg* {.bycopy.} = object
    nfgen_family*: uint8        ##  AF_xxx
    version*: uint8             ##  nfnetlink version
    res_id*: int16            ##  resource id

  nlmsghdr* {.bycopy.} = object
    nlmsg_len*: uint32          ##  Length of message including header
    nlmsg_type*: uint16         ##  Message content
    nlmsg_flags*: uint16        ##  Additional flags
    nlmsg_seq*: uint32          ##  Sequence number
    nlmsg_pid*: uint32          ##  Sending process port ID

  nfqnl_msg_packet_hdr* {.bycopy, packed.} = object
    packet_id*: int32         ##  unique ID of packet in queue
    hw_protocol*: int16       ##  hw protocol (network order)
    hook*: uint8                ##  netfilter hook

  nfqnl_msg_packet_hw* {.bycopy.} = object
    hw_addrlen*: int16
    pad*: uint16
    hw_addr*: array[8, uint8]

  nfqnl_msg_packet_timestamp* {.bycopy.} = object
    sec* {.align: 8.}: int64
    usec* {.align: 8.}: int64

  nfqnl_attr_type* = enum
    NFQA_UNSPEC, NFQA_PACKET_HDR, NFQA_VERDICT_HDR, ##  nfqnl_msg_verdict_hrd
    NFQA_MARK,                ##  uint32 nfmark
    NFQA_TIMESTAMP,           ##  nfqnl_msg_packet_timestamp
    NFQA_IFINDEX_INDEV,       ##  uint32 ifindex
    NFQA_IFINDEX_OUTDEV,      ##  uint32 ifindex
    NFQA_IFINDEX_PHYSINDEV,   ##  uint32 ifindex
    NFQA_IFINDEX_PHYSOUTDEV,  ##  uint32 ifindex
    NFQA_HWADDR,              ##  nfqnl_msg_packet_hw
    NFQA_PAYLOAD,             ##  opaque data payload
    NFQA_CT,                  ##  nf_conntrack_netlink.h
    NFQA_CT_INFO,             ##  enum ip_conntrack_info
    NFQA_CAP_LEN,             ##  uint32 length of captured packet
    NFQA_SKB_INFO,            ##  uint32 skb meta information
    NFQA_EXP,                 ##  nf_conntrack_netlink.h
    NFQA_UID,                 ##  uint32 sk uid
    NFQA_GID,                 ##  uint32 sk gid
    NFQA_SECCTX,              ##  security context string
    NFQA_MAX


type
  nfqnl_msg_verdict_hdr* {.bycopy.} = object
    verdict*: int32
    id*: int32

  nfqnl_msg_config_cmds* = enum
    NFQNL_CFG_CMD_NONE, NFQNL_CFG_CMD_BIND, NFQNL_CFG_CMD_UNBIND,
    NFQNL_CFG_CMD_PF_BIND, NFQNL_CFG_CMD_PF_UNBIND


type
  nfqnl_msg_config_cmd* {.bycopy.} = object
    command*: uint8             ##  nfqnl_msg_config_cmds
    pad*: uint8
    pf*: int16                ##  AF_xxx for PF_[UN]BIND

  nfqnl_config_mode* = enum
    NFQNL_COPY_NONE, NFQNL_COPY_META, NFQNL_COPY_PACKET


type
  nfqnl_msg_config_params* {.bycopy, packed.} = object
    copy_range*: int32
    copy_mode*: uint8           ##  enum nfqnl_config_mode

  nfqnl_attr_config* = enum
    NFQA_CFG_UNSPEC, NFQA_CFG_CMD, ##  nfqnl_msg_config_cmd
    NFQA_CFG_PARAMS,          ##  nfqnl_msg_config_params
    NFQA_CFG_QUEUE_MAXLEN,    ##  uint32
    NFQA_CFG_MASK,            ##  identify which flags to change
    NFQA_CFG_FLAGS,           ##  value of these flags (uint32)
    NFQA_CFG_MAX

##  Flags for NFQA_CFG_FLAGS

const
  NFQA_CFG_F_FAIL_OPEN* = (1 shl 0)
  NFQA_CFG_F_CONNTRACK* = (1 shl 1)
  NFQA_CFG_F_GSO* = (1 shl 2)
  NFQA_CFG_F_UID_GID* = (1 shl 3)
  NFQA_CFG_F_SECCTX* = (1 shl 4)
  NFQA_CFG_F_MAX* = (1 shl 5)

##  flags for NFQA_SKB_INFO
##  packet appears to have wrong checksums, but they are ok

const
  NFQA_SKB_CSUMNOTREADY* = (1 shl 0)

##  packet is GSO (i.e., exceeds device mtu)

const
  NFQA_SKB_GSO* = (1 shl 1)

##  csum not validated (incoming device doesn't support hw checksum, etc.)

const
  NFQA_SKB_CSUM_NOTVERIFIED* = (1 shl 2)
