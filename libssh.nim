{.deadCodeElim: on.}

when defined(Windows):
  const 
        libsshSONAME = "ssh.dll"
elif defined(MacOSX):
  const 
        libsshSONAME = "libssh.dylib"
else:
  const 
        libsshSONAME = "libssh.so"

type
  timeval* = object
  mode_t* = cint
  fd_set* = ptr object
  uid_t* =  cint
  gid_t* = cint
  ssize_t* = cint
  sftp_ext_struct* = ptr object

template SSH_STRINGIFY*(s: untyped): untyped =
  SSH_TOSTRING(s)

template SSH_VERSION_INT*(a, b, c: untyped): untyped =
  ((a) shl 16 or (b) shl 8 or (c))

template SSH_VERSION*(a, b, c: untyped): untyped =
  $a & "." & $b & "." & $c

const
  LIBSSH_VERSION_MAJOR* = 0
  LIBSSH_VERSION_MINOR* = 9
  LIBSSH_VERSION_MICRO* = 0
  LIBSSH_VERSION_INT* = SSH_VERSION_INT(LIBSSH_VERSION_MAJOR, LIBSSH_VERSION_MINOR,
                                      LIBSSH_VERSION_MICRO)
  LIBSSH_VERSION* = SSH_VERSION(LIBSSH_VERSION_MAJOR, LIBSSH_VERSION_MINOR,
                              LIBSSH_VERSION_MICRO)

type
  ssh_counter_struct* {.bycopy.} = object
    in_bytes*: uint64
    out_bytes*: uint64
    in_packets*: uint64
    out_packets*: uint64

  ssh_counter* = ptr object
  ssh_agent* = ptr object
  ssh_buffer* = ptr object
  ssh_channel* = ptr object
  ssh_message* = ptr object
  ssh_pcap_file* = ptr object
  ssh_key* = ptr object
  ssh_scp* = ptr object
  ssh_session* = ptr object
  ssh_string* = ptr object
  ssh_event* = ptr object
  ssh_connector* = ptr object
  ssh_gssapi_creds* = pointer
  socket_t* = cint
  ssh_kex_types_e* {.size: sizeof(cint).} = enum
    SSH_KEX = 0, SSH_HOSTKEYS, SSH_CRYPT_C_S, SSH_CRYPT_S_C, SSH_MAC_C_S, SSH_MAC_S_C,
    SSH_COMP_C_S, SSH_COMP_S_C, SSH_LANG_C_S, SSH_LANG_S_C


const
  SSH_CRYPT* = 2
  SSH_MAC* = 3
  SSH_COMP* = 4
  SSH_LANG* = 5

type
  ssh_auth_e* {.size: sizeof(cint).} = enum
    SSH_AUTH_ERROR = -1, SSH_AUTH_SUCCESS = 0, SSH_AUTH_DENIED, SSH_AUTH_PARTIAL,
    SSH_AUTH_INFO, SSH_AUTH_AGAIN


const
  SSH_AUTH_METHOD_UNKNOWN* = 0
  SSH_AUTH_METHOD_NONE* = 0x00000001
  SSH_AUTH_METHOD_PASSWORD* = 0x00000002
  SSH_AUTH_METHOD_PUBLICKEY* = 0x00000004
  SSH_AUTH_METHOD_HOSTBASED* = 0x00000008
  SSH_AUTH_METHOD_INTERACTIVE* = 0x00000010
  SSH_AUTH_METHOD_GSSAPI_MIC* = 0x00000020

type
  ssh_requests_e* {.size: sizeof(cint).} = enum
    SSH_REQUEST_AUTH = 1, SSH_REQUEST_CHANNEL_OPEN, SSH_REQUEST_CHANNEL,
    SSH_REQUEST_SERVICE, SSH_REQUEST_GLOBAL


type
  ssh_channel_type_e* {.size: sizeof(cint).} = enum
    SSH_CHANNEL_UNKNOWN = 0, SSH_CHANNEL_SESSION, SSH_CHANNEL_DIRECT_TCPIP,
    SSH_CHANNEL_FORWARDED_TCPIP, SSH_CHANNEL_X11, SSH_CHANNEL_AUTH_AGENT


type
  ssh_channel_requests_e* {.size: sizeof(cint).} = enum
    SSH_CHANNEL_REQUEST_UNKNOWN = 0, SSH_CHANNEL_REQUEST_PTY,
    SSH_CHANNEL_REQUEST_EXEC, SSH_CHANNEL_REQUEST_SHELL, SSH_CHANNEL_REQUEST_ENV,
    SSH_CHANNEL_REQUEST_SUBSYSTEM, SSH_CHANNEL_REQUEST_WINDOW_CHANGE,
    SSH_CHANNEL_REQUEST_X11


type
  ssh_global_requests_e* {.size: sizeof(cint).} = enum
    SSH_GLOBAL_REQUEST_UNKNOWN = 0, SSH_GLOBAL_REQUEST_TCPIP_FORWARD,
    SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD, SSH_GLOBAL_REQUEST_KEEPALIVE


type
  ssh_publickey_state_e* {.size: sizeof(cint).} = enum
    SSH_PUBLICKEY_STATE_ERROR = -1, SSH_PUBLICKEY_STATE_NONE = 0,
    SSH_PUBLICKEY_STATE_VALID = 1, SSH_PUBLICKEY_STATE_WRONG = 2


const
  SSH_CLOSED* = 0x00000001
  SSH_READ_PENDING* = 0x00000002
  SSH_CLOSED_ERROR* = 0x00000004
  SSH_WRITE_PENDING* = 0x00000008

type
  ssh_server_known_e* {.size: sizeof(cint).} = enum
    SSH_SERVER_ERROR = -1, SSH_SERVER_NOT_KNOWN = 0, SSH_SERVER_KNOWN_OK,
    SSH_SERVER_KNOWN_CHANGED, SSH_SERVER_FOUND_OTHER, SSH_SERVER_FILE_NOT_FOUND


type
  ssh_known_hosts_e* {.size: sizeof(cint).} = enum
    SSH_KNOWN_HOSTS_ERROR = -2, SSH_KNOWN_HOSTS_NOT_FOUND = -1,
    SSH_KNOWN_HOSTS_UNKNOWN = 0, SSH_KNOWN_HOSTS_OK, SSH_KNOWN_HOSTS_CHANGED,
    SSH_KNOWN_HOSTS_OTHER


const
  MD5_DIGEST_LEN* = 16

type
  ssh_error_types_e* {.size: sizeof(cint).} = enum
    SSH_NO_ERROR = 0, SSH_REQUEST_DENIED, SSH_FATAL, SSH_EINTR


type
  ssh_keytypes_e* {.size: sizeof(cint).} = enum
    SSH_KEYTYPE_UNKNOWN = 0, SSH_KEYTYPE_DSS = 1, SSH_KEYTYPE_RSA, SSH_KEYTYPE_RSA1,
    SSH_KEYTYPE_ECDSA, SSH_KEYTYPE_ED25519, SSH_KEYTYPE_DSS_CERT01,
    SSH_KEYTYPE_RSA_CERT01, SSH_KEYTYPE_ECDSA_P256, SSH_KEYTYPE_ECDSA_P384,
    SSH_KEYTYPE_ECDSA_P521, SSH_KEYTYPE_ECDSA_P256_CERT01,
    SSH_KEYTYPE_ECDSA_P384_CERT01, SSH_KEYTYPE_ECDSA_P521_CERT01,
    SSH_KEYTYPE_ED25519_CERT01


type
  ssh_keycmp_e* {.size: sizeof(cint).} = enum
    SSH_KEY_CMP_PUBLIC = 0, SSH_KEY_CMP_PRIVATE


const
  SSH_ADDRSTRLEN* = 46

type
  ssh_knownhosts_entry* {.bycopy.} = object
    hostname*: cstring
    unparsed*: cstring
    publickey*: ssh_key
    comment*: cstring


const
  SSH_OK* = 0
  SSH_ERROR* = -1
  SSH_AGAIN* = -2
  SSH_EOF* = -127

const
  SSH_LOG_NOLOG* = 0
  SSH_LOG_WARNING* = 1
  SSH_LOG_PROTOCOL* = 2
  SSH_LOG_PACKET* = 3
  SSH_LOG_FUNCTIONS* = 4

const
  SSH_LOG_RARE* = SSH_LOG_WARNING
  SSH_LOG_NONE* = 0
  SSH_LOG_WARN* = 1
  SSH_LOG_INFO* = 2
  SSH_LOG_DEBUG* = 3
  SSH_LOG_TRACE* = 4

type
  ssh_options_e* {.size: sizeof(cint).} = enum
    SSH_OPTIONS_HOST, SSH_OPTIONS_PORT, SSH_OPTIONS_PORT_STR, SSH_OPTIONS_FD,
    SSH_OPTIONS_USER, SSH_OPTIONS_SSH_DIR, SSH_OPTIONS_IDENTITY,
    SSH_OPTIONS_ADD_IDENTITY, SSH_OPTIONS_KNOWNHOSTS, SSH_OPTIONS_TIMEOUT,
    SSH_OPTIONS_TIMEOUT_USEC, SSH_OPTIONS_SSH1, SSH_OPTIONS_SSH2,
    SSH_OPTIONS_LOG_VERBOSITY, SSH_OPTIONS_LOG_VERBOSITY_STR,
    SSH_OPTIONS_CIPHERS_C_S, SSH_OPTIONS_CIPHERS_S_C, SSH_OPTIONS_COMPRESSION_C_S,
    SSH_OPTIONS_COMPRESSION_S_C, SSH_OPTIONS_PROXYCOMMAND, SSH_OPTIONS_BINDADDR,
    SSH_OPTIONS_STRICTHOSTKEYCHECK, SSH_OPTIONS_COMPRESSION,
    SSH_OPTIONS_COMPRESSION_LEVEL, SSH_OPTIONS_KEY_EXCHANGE, SSH_OPTIONS_HOSTKEYS,
    SSH_OPTIONS_GSSAPI_SERVER_IDENTITY, SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY,
    SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS, SSH_OPTIONS_HMAC_C_S,
    SSH_OPTIONS_HMAC_S_C, SSH_OPTIONS_PASSWORD_AUTH, SSH_OPTIONS_PUBKEY_AUTH,
    SSH_OPTIONS_KBDINT_AUTH, SSH_OPTIONS_GSSAPI_AUTH,
    SSH_OPTIONS_GLOBAL_KNOWNHOSTS, SSH_OPTIONS_NODELAY,
    SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, SSH_OPTIONS_PROCESS_CONFIG,
    SSH_OPTIONS_REKEY_DATA, SSH_OPTIONS_REKEY_TIME


const
  SSH_SCP_WRITE* = 0
  SSH_SCP_READ* = 1
  SSH_SCP_RECURSIVE* = 0x00000010

type
  ssh_scp_request_types* {.size: sizeof(cint).} = enum
    SSH_SCP_REQUEST_NEWDIR = 1, SSH_SCP_REQUEST_NEWFILE, SSH_SCP_REQUEST_EOF,
    SSH_SCP_REQUEST_ENDDIR, SSH_SCP_REQUEST_WARNING


type
  ssh_connector_flags_e* {.size: sizeof(cint).} = enum
    SSH_CONNECTOR_STDOUT = 1, SSH_CONNECTOR_STDERR = 2, SSH_CONNECTOR_BOTH = 3


proc ssh_blocking_flush*(session: ssh_session; timeout: cint): cint {.cdecl,
    importc: "ssh_blocking_flush", dynlib: libsshSONAME.}
proc ssh_channel_accept_x11*(channel: ssh_channel; timeout_ms: cint): ssh_channel {.
    cdecl, importc: "ssh_channel_accept_x11", dynlib: libsshSONAME.}
proc ssh_channel_change_pty_size*(channel: ssh_channel; cols: cint; rows: cint): cint {.
    cdecl, importc: "ssh_channel_change_pty_size", dynlib: libsshSONAME.}
proc ssh_channel_close*(channel: ssh_channel): cint {.cdecl,
    importc: "ssh_channel_close", dynlib: libsshSONAME.}
proc ssh_channel_free*(channel: ssh_channel) {.cdecl, importc: "ssh_channel_free",
    dynlib: libsshSONAME.}
proc ssh_channel_get_exit_status*(channel: ssh_channel): cint {.cdecl,
    importc: "ssh_channel_get_exit_status", dynlib: libsshSONAME.}
proc ssh_channel_get_session*(channel: ssh_channel): ssh_session {.cdecl,
    importc: "ssh_channel_get_session", dynlib: libsshSONAME.}
proc ssh_channel_is_closed*(channel: ssh_channel): cint {.cdecl,
    importc: "ssh_channel_is_closed", dynlib: libsshSONAME.}
proc ssh_channel_is_eof*(channel: ssh_channel): cint {.cdecl,
    importc: "ssh_channel_is_eof", dynlib: libsshSONAME.}
proc ssh_channel_is_open*(channel: ssh_channel): cint {.cdecl,
    importc: "ssh_channel_is_open", dynlib: libsshSONAME.}
proc ssh_channel_new*(session: ssh_session): ssh_channel {.cdecl,
    importc: "ssh_channel_new", dynlib: libsshSONAME.}
proc ssh_channel_open_auth_agent*(channel: ssh_channel): cint {.cdecl,
    importc: "ssh_channel_open_auth_agent", dynlib: libsshSONAME.}
proc ssh_channel_open_forward*(channel: ssh_channel; remotehost: cstring;
                              remoteport: cint; sourcehost: cstring; localport: cint): cint {.
    cdecl, importc: "ssh_channel_open_forward", dynlib: libsshSONAME.}
proc ssh_channel_open_forward_unix*(channel: ssh_channel; remotepath: cstring;
                                   sourcehost: cstring; localport: cint): cint {.
    cdecl, importc: "ssh_channel_open_forward_unix", dynlib: libsshSONAME.}
proc ssh_channel_open_session*(channel: ssh_channel): cint {.cdecl,
    importc: "ssh_channel_open_session", dynlib: libsshSONAME.}
proc ssh_channel_open_x11*(channel: ssh_channel; orig_addr: cstring; orig_port: cint): cint {.
    cdecl, importc: "ssh_channel_open_x11", dynlib: libsshSONAME.}
proc ssh_channel_poll*(channel: ssh_channel; is_stderr: cint): cint {.cdecl,
    importc: "ssh_channel_poll", dynlib: libsshSONAME.}
proc ssh_channel_poll_timeout*(channel: ssh_channel; timeout: cint; is_stderr: cint): cint {.
    cdecl, importc: "ssh_channel_poll_timeout", dynlib: libsshSONAME.}
proc ssh_channel_read*(channel: ssh_channel; dest: pointer; count: uint32;
                      is_stderr: cint): cint {.cdecl, importc: "ssh_channel_read",
    dynlib: libsshSONAME.}
proc ssh_channel_read_timeout*(channel: ssh_channel; dest: pointer; count: uint32;
                              is_stderr: cint; timeout_ms: cint): cint {.cdecl,
    importc: "ssh_channel_read_timeout", dynlib: libsshSONAME.}
proc ssh_channel_read_nonblocking*(channel: ssh_channel; dest: pointer;
                                  count: uint32; is_stderr: cint): cint {.cdecl,
    importc: "ssh_channel_read_nonblocking", dynlib: libsshSONAME.}
proc ssh_channel_request_env*(channel: ssh_channel; name: cstring; value: cstring): cint {.
    cdecl, importc: "ssh_channel_request_env", dynlib: libsshSONAME.}
proc ssh_channel_request_exec*(channel: ssh_channel; cmd: cstring): cint {.cdecl,
    importc: "ssh_channel_request_exec", dynlib: libsshSONAME.}
proc ssh_channel_request_pty*(channel: ssh_channel): cint {.cdecl,
    importc: "ssh_channel_request_pty", dynlib: libsshSONAME.}
proc ssh_channel_request_pty_size*(channel: ssh_channel; term: cstring; cols: cint;
                                  rows: cint): cint {.cdecl,
    importc: "ssh_channel_request_pty_size", dynlib: libsshSONAME.}
proc ssh_channel_request_shell*(channel: ssh_channel): cint {.cdecl,
    importc: "ssh_channel_request_shell", dynlib: libsshSONAME.}
proc ssh_channel_request_send_signal*(channel: ssh_channel; signum: cstring): cint {.
    cdecl, importc: "ssh_channel_request_send_signal", dynlib: libsshSONAME.}
proc ssh_channel_request_send_break*(channel: ssh_channel; length: uint32): cint {.
    cdecl, importc: "ssh_channel_request_send_break", dynlib: libsshSONAME.}
proc ssh_channel_request_sftp*(channel: ssh_channel): cint {.cdecl,
    importc: "ssh_channel_request_sftp", dynlib: libsshSONAME.}
proc ssh_channel_request_subsystem*(channel: ssh_channel; subsystem: cstring): cint {.
    cdecl, importc: "ssh_channel_request_subsystem", dynlib: libsshSONAME.}
proc ssh_channel_request_x11*(channel: ssh_channel; single_connection: cint;
                             protocol: cstring; cookie: cstring; screen_number: cint): cint {.
    cdecl, importc: "ssh_channel_request_x11", dynlib: libsshSONAME.}
proc ssh_channel_request_auth_agent*(channel: ssh_channel): cint {.cdecl,
    importc: "ssh_channel_request_auth_agent", dynlib: libsshSONAME.}
proc ssh_channel_send_eof*(channel: ssh_channel): cint {.cdecl,
    importc: "ssh_channel_send_eof", dynlib: libsshSONAME.}
proc ssh_channel_select*(readchans: ssh_channel; writechans: ssh_channel;
                        exceptchans: ssh_channel; timeout: ptr timeval): cint {.
    cdecl, importc: "ssh_channel_select", dynlib: libsshSONAME.}
proc ssh_channel_set_blocking*(channel: ssh_channel; blocking: cint) {.cdecl,
    importc: "ssh_channel_set_blocking", dynlib: libsshSONAME.}
proc ssh_channel_set_counter*(channel: ssh_channel; counter: ssh_counter) {.cdecl,
    importc: "ssh_channel_set_counter", dynlib: libsshSONAME.}
proc ssh_channel_write*(channel: ssh_channel; data: pointer; len: uint32): cint {.
    cdecl, importc: "ssh_channel_write", dynlib: libsshSONAME.}
proc ssh_channel_write_stderr*(channel: ssh_channel; data: pointer; len: uint32): cint {.
    cdecl, importc: "ssh_channel_write_stderr", dynlib: libsshSONAME.}
proc ssh_channel_window_size*(channel: ssh_channel): uint32 {.cdecl,
    importc: "ssh_channel_window_size", dynlib: libsshSONAME.}
proc ssh_basename*(path: cstring): cstring {.cdecl, importc: "ssh_basename",
    dynlib: libsshSONAME.}
proc ssh_clean_pubkey_hash*(hash: ptr cstring) {.cdecl,
    importc: "ssh_clean_pubkey_hash", dynlib: libsshSONAME.}
proc ssh_connect*(session: ssh_session): cint {.cdecl, importc: "ssh_connect",
    dynlib: libsshSONAME.}
proc ssh_connector_new*(session: ssh_session): ssh_connector {.cdecl,
    importc: "ssh_connector_new", dynlib: libsshSONAME.}
proc ssh_connector_free*(connector: ssh_connector) {.cdecl,
    importc: "ssh_connector_free", dynlib: libsshSONAME.}
proc ssh_connector_set_in_channel*(connector: ssh_connector; channel: ssh_channel;
                                  flags: ssh_connector_flags_e): cint {.cdecl,
    importc: "ssh_connector_set_in_channel", dynlib: libsshSONAME.}
proc ssh_connector_set_out_channel*(connector: ssh_connector; channel: ssh_channel;
                                   flags: ssh_connector_flags_e): cint {.cdecl,
    importc: "ssh_connector_set_out_channel", dynlib: libsshSONAME.}
proc ssh_connector_set_in_fd*(connector: ssh_connector; fd: socket_t) {.cdecl,
    importc: "ssh_connector_set_in_fd", dynlib: libsshSONAME.}
proc ssh_connector_set_out_fd*(connector: ssh_connector; fd: socket_t) {.cdecl,
    importc: "ssh_connector_set_out_fd", dynlib: libsshSONAME.}
proc ssh_copyright*(): cstring {.cdecl, importc: "ssh_copyright", dynlib: libsshSONAME.}
proc ssh_disconnect*(session: ssh_session) {.cdecl, importc: "ssh_disconnect",
    dynlib: libsshSONAME.}
proc ssh_dirname*(path: cstring): cstring {.cdecl, importc: "ssh_dirname",
                                        dynlib: libsshSONAME.}
proc ssh_finalize*(): cint {.cdecl, importc: "ssh_finalize", dynlib: libsshSONAME.}
proc ssh_channel_accept_forward*(session: ssh_session; timeout_ms: cint;
                                destination_port: ptr cint): ssh_channel {.cdecl,
    importc: "ssh_channel_accept_forward", dynlib: libsshSONAME.}
proc ssh_channel_cancel_forward*(session: ssh_session; address: cstring; port: cint): cint {.
    cdecl, importc: "ssh_channel_cancel_forward", dynlib: libsshSONAME.}
proc ssh_channel_listen_forward*(session: ssh_session; address: cstring; port: cint;
                                bound_port: ptr cint): cint {.cdecl,
    importc: "ssh_channel_listen_forward", dynlib: libsshSONAME.}
proc ssh_free*(session: ssh_session) {.cdecl, importc: "ssh_free",
                                    dynlib: libsshSONAME.}
proc ssh_get_disconnect_message*(session: ssh_session): cstring {.cdecl,
    importc: "ssh_get_disconnect_message", dynlib: libsshSONAME.}
proc ssh_get_error*(error: pointer): cstring {.cdecl, importc: "ssh_get_error",
    dynlib: libsshSONAME.}
proc ssh_get_error_code*(error: pointer): cint {.cdecl,
    importc: "ssh_get_error_code", dynlib: libsshSONAME.}
proc ssh_get_fd*(session: ssh_session): socket_t {.cdecl, importc: "ssh_get_fd",
    dynlib: libsshSONAME.}
proc ssh_get_hexa*(what: cstring; len: csize): cstring {.cdecl,
    importc: "ssh_get_hexa", dynlib: libsshSONAME.}
proc ssh_get_issue_banner*(session: ssh_session): cstring {.cdecl,
    importc: "ssh_get_issue_banner", dynlib: libsshSONAME.}
proc ssh_get_openssh_version*(session: ssh_session): cint {.cdecl,
    importc: "ssh_get_openssh_version", dynlib: libsshSONAME.}
proc ssh_get_server_publickey*(session: ssh_session; key: ssh_key): cint {.cdecl,
    importc: "ssh_get_server_publickey", dynlib: libsshSONAME.}
type
  ssh_publickey_hash_type* {.size: sizeof(cint).} = enum
    SSH_PUBLICKEY_HASH_SHA1, SSH_PUBLICKEY_HASH_MD5, SSH_PUBLICKEY_HASH_SHA256


proc ssh_get_publickey_hash*(key: ssh_key; `type`: ssh_publickey_hash_type;
                            hash: ptr cstring; hlen: ptr csize): cint {.cdecl,
    importc: "ssh_get_publickey_hash", dynlib: libsshSONAME.}
proc ssh_get_pubkey_hash*(session: ssh_session; hash: ptr cstring): cint {.cdecl,
    importc: "ssh_get_pubkey_hash", dynlib: libsshSONAME.}
proc ssh_forward_accept*(session: ssh_session; timeout_ms: cint): ssh_channel {.cdecl,
    importc: "ssh_forward_accept", dynlib: libsshSONAME.}
proc ssh_forward_cancel*(session: ssh_session; address: cstring; port: cint): cint {.
    cdecl, importc: "ssh_forward_cancel", dynlib: libsshSONAME.}
proc ssh_forward_listen*(session: ssh_session; address: cstring; port: cint;
                        bound_port: ptr cint): cint {.cdecl,
    importc: "ssh_forward_listen", dynlib: libsshSONAME.}
proc ssh_get_publickey*(session: ssh_session; key: ssh_key): cint {.cdecl,
    importc: "ssh_get_publickey", dynlib: libsshSONAME.}
proc ssh_write_knownhost*(session: ssh_session): cint {.cdecl,
    importc: "ssh_write_knownhost", dynlib: libsshSONAME.}
proc ssh_dump_knownhost*(session: ssh_session): cstring {.cdecl,
    importc: "ssh_dump_knownhost", dynlib: libsshSONAME.}
proc ssh_is_server_known*(session: ssh_session): cint {.cdecl,
    importc: "ssh_is_server_known", dynlib: libsshSONAME.}
proc ssh_print_hexa*(descr: cstring; what: cstring; len: csize) {.cdecl,
    importc: "ssh_print_hexa", dynlib: libsshSONAME.}
proc ssh_get_random*(where: pointer; len: cint; strong: cint): cint {.cdecl,
    importc: "ssh_get_random", dynlib: libsshSONAME.}
proc ssh_get_version*(session: ssh_session): cint {.cdecl,
    importc: "ssh_get_version", dynlib: libsshSONAME.}
proc ssh_get_status*(session: ssh_session): cint {.cdecl, importc: "ssh_get_status",
    dynlib: libsshSONAME.}
proc ssh_get_poll_flags*(session: ssh_session): cint {.cdecl,
    importc: "ssh_get_poll_flags", dynlib: libsshSONAME.}
proc ssh_init*(): cint {.cdecl, importc: "ssh_init", dynlib: libsshSONAME.}
proc ssh_is_blocking*(session: ssh_session): cint {.cdecl,
    importc: "ssh_is_blocking", dynlib: libsshSONAME.}
proc ssh_is_connected*(session: ssh_session): cint {.cdecl,
    importc: "ssh_is_connected", dynlib: libsshSONAME.}
proc ssh_knownhosts_entry_free*(entry: ssh_knownhosts_entry) {.cdecl,
    importc: "ssh_knownhosts_entry_free", dynlib: libsshSONAME.}
template SSH_KNOWNHOSTS_ENTRY_FREE*(e: untyped): void =
  while true:
    if (e) != nil:
      ssh_knownhosts_entry_free(e)
      e = nil
    if not 0:
      break

proc ssh_known_hosts_parse_line*(host: cstring; line: cstring;
                                entry: ptr ssh_knownhosts_entry): cint {.cdecl,
    importc: "ssh_known_hosts_parse_line", dynlib: libsshSONAME.}
proc ssh_session_has_known_hosts_entry*(session: ssh_session): ssh_known_hosts_e {.
    cdecl, importc: "ssh_session_has_known_hosts_entry", dynlib: libsshSONAME.}
proc ssh_session_export_known_hosts_entry*(session: ssh_session;
    pentry_string: cstringArray): cint {.cdecl, importc: "ssh_session_export_known_hosts_entry",
                                      dynlib: libsshSONAME.}
proc ssh_session_update_known_hosts*(session: ssh_session): cint {.cdecl,
    importc: "ssh_session_update_known_hosts", dynlib: libsshSONAME.}
proc ssh_session_get_known_hosts_entry*(session: ssh_session;
                                       pentry: ptr ssh_knownhosts_entry): ssh_known_hosts_e {.
    cdecl, importc: "ssh_session_get_known_hosts_entry", dynlib: libsshSONAME.}
proc ssh_session_is_known_server*(session: ssh_session): ssh_known_hosts_e {.cdecl,
    importc: "ssh_session_is_known_server", dynlib: libsshSONAME.}
proc ssh_set_log_level*(level: cint): cint {.cdecl, importc: "ssh_set_log_level",
    dynlib: libsshSONAME.}
proc ssh_get_log_level*(): cint {.cdecl, importc: "ssh_get_log_level",
                               dynlib: libsshSONAME.}
proc ssh_get_log_userdata*(): pointer {.cdecl, importc: "ssh_get_log_userdata",
                                     dynlib: libsshSONAME.}
proc ssh_set_log_userdata*(data: pointer): cint {.cdecl,
    importc: "ssh_set_log_userdata", dynlib: libsshSONAME.}
proc x_ssh_log*(verbosity: cint; function: cstring; format: cstring) {.varargs, cdecl,
    importc: "x_ssh_log", dynlib: libsshSONAME.}
proc ssh_log*(session: ssh_session; prioriry: cint; format: cstring) {.varargs, cdecl,
    importc: "ssh_log", dynlib: libsshSONAME.}
proc ssh_message_channel_request_open_reply_accept*(msg: ssh_message): ssh_channel {.
    cdecl, importc: "ssh_message_channel_request_open_reply_accept",
    dynlib: libsshSONAME.}
proc ssh_message_channel_request_open_reply_accept_channel*(msg: ssh_message;
    chan: ssh_channel): cint {.cdecl, importc: "ssh_message_channel_request_open_reply_accept_channel",
                            dynlib: libsshSONAME.}
proc ssh_message_channel_request_reply_success*(msg: ssh_message): cint {.cdecl,
    importc: "ssh_message_channel_request_reply_success", dynlib: libsshSONAME.}
template SSH_MESSAGE_FREE*(x: untyped): void =
  while true:
    if (x) != nil:
      ssh_message_free(x)
      (x) = nil
    if not 0:
      break

proc ssh_message_free*(msg: ssh_message) {.cdecl, importc: "ssh_message_free",
                                        dynlib: libsshSONAME.}
proc ssh_message_get*(session: ssh_session): ssh_message {.cdecl,
    importc: "ssh_message_get", dynlib: libsshSONAME.}
proc ssh_message_subtype*(msg: ssh_message): cint {.cdecl,
    importc: "ssh_message_subtype", dynlib: libsshSONAME.}
proc ssh_message_type*(msg: ssh_message): cint {.cdecl, importc: "ssh_message_type",
    dynlib: libsshSONAME.}
proc ssh_mkdir*(pathname: cstring; mode: mode_t): cint {.cdecl, importc: "ssh_mkdir",
    dynlib: libsshSONAME.}
proc ssh_new*(): ssh_session {.cdecl, importc: "ssh_new", dynlib: libsshSONAME.}
proc ssh_options_copy*(src: ssh_session; dest: ssh_session): cint {.cdecl,
    importc: "ssh_options_copy", dynlib: libsshSONAME.}
proc ssh_options_getopt*(session: ssh_session; argcptr: ptr cint; argv: cstringArray): cint {.
    cdecl, importc: "ssh_options_getopt", dynlib: libsshSONAME.}
proc ssh_options_parse_config*(session: ssh_session; filename: cstring): cint {.cdecl,
    importc: "ssh_options_parse_config", dynlib: libsshSONAME.}
proc ssh_options_set*(session: ssh_session; `type`: ssh_options_e; value: pointer): cint {.
    cdecl, importc: "ssh_options_set", dynlib: libsshSONAME.}
proc ssh_options_get*(session: ssh_session; `type`: ssh_options_e;
                     value: cstringArray): cint {.cdecl, importc: "ssh_options_get",
    dynlib: libsshSONAME.}
proc ssh_options_get_port*(session: ssh_session; port_target: ptr cuint): cint {.cdecl,
    importc: "ssh_options_get_port", dynlib: libsshSONAME.}
proc ssh_pcap_file_close*(pcap: ssh_pcap_file): cint {.cdecl,
    importc: "ssh_pcap_file_close", dynlib: libsshSONAME.}
proc ssh_pcap_file_free*(pcap: ssh_pcap_file) {.cdecl,
    importc: "ssh_pcap_file_free", dynlib: libsshSONAME.}
proc ssh_pcap_file_new*(): ssh_pcap_file {.cdecl, importc: "ssh_pcap_file_new",
                                        dynlib: libsshSONAME.}
proc ssh_pcap_file_open*(pcap: ssh_pcap_file; filename: cstring): cint {.cdecl,
    importc: "ssh_pcap_file_open", dynlib: libsshSONAME.}
type
  ssh_auth_callback* = proc (prompt: cstring; buf: cstring; len: csize; echo: cint;
                          verify: cint; userdata: pointer): cint {.cdecl.}

proc ssh_key_new*(): ssh_key {.cdecl, importc: "ssh_key_new", dynlib: libsshSONAME.}
template SSH_KEY_FREE*(x: untyped): void =
  while true:
    if (x) != nil:
      ssh_key_free(x)
      x = nil
    if not 0:
      break

proc ssh_key_free*(key: ssh_key) {.cdecl, importc: "ssh_key_free",
                                dynlib: libsshSONAME.}
proc ssh_key_type*(key: ssh_key): ssh_keytypes_e {.cdecl, importc: "ssh_key_type",
    dynlib: libsshSONAME.}
proc ssh_key_type_to_char*(`type`: ssh_keytypes_e): cstring {.cdecl,
    importc: "ssh_key_type_to_char", dynlib: libsshSONAME.}
proc ssh_key_type_from_name*(name: cstring): ssh_keytypes_e {.cdecl,
    importc: "ssh_key_type_from_name", dynlib: libsshSONAME.}
proc ssh_key_is_public*(k: ssh_key): cint {.cdecl, importc: "ssh_key_is_public",
                                        dynlib: libsshSONAME.}
proc ssh_key_is_private*(k: ssh_key): cint {.cdecl, importc: "ssh_key_is_private",
    dynlib: libsshSONAME.}
proc ssh_key_cmp*(k1: ssh_key; k2: ssh_key; what: ssh_keycmp_e): cint {.cdecl,
    importc: "ssh_key_cmp", dynlib: libsshSONAME.}
proc ssh_pki_generate*(`type`: ssh_keytypes_e; parameter: cint; pkey: ssh_key): cint {.
    cdecl, importc: "ssh_pki_generate", dynlib: libsshSONAME.}
proc ssh_pki_import_privkey_base64*(b64_key: cstring; passphrase: cstring;
                                   auth_fn: ssh_auth_callback; auth_data: pointer;
                                   pkey: ssh_key): cint {.cdecl,
    importc: "ssh_pki_import_privkey_base64", dynlib: libsshSONAME.}
proc ssh_pki_export_privkey_base64*(privkey: ssh_key; passphrase: cstring;
                                   auth_fn: ssh_auth_callback; auth_data: pointer;
                                   b64_key: cstringArray): cint {.cdecl,
    importc: "ssh_pki_export_privkey_base64", dynlib: libsshSONAME.}
proc ssh_pki_import_privkey_file*(filename: cstring; passphrase: cstring;
                                 auth_fn: ssh_auth_callback; auth_data: pointer;
                                 pkey: ssh_key): cint {.cdecl,
    importc: "ssh_pki_import_privkey_file", dynlib: libsshSONAME.}
proc ssh_pki_export_privkey_file*(privkey: ssh_key; passphrase: cstring;
                                 auth_fn: ssh_auth_callback; auth_data: pointer;
                                 filename: cstring): cint {.cdecl,
    importc: "ssh_pki_export_privkey_file", dynlib: libsshSONAME.}
proc ssh_pki_copy_cert_to_privkey*(cert_key: ssh_key; privkey: ssh_key): cint {.cdecl,
    importc: "ssh_pki_copy_cert_to_privkey", dynlib: libsshSONAME.}
proc ssh_pki_import_pubkey_base64*(b64_key: cstring; `type`: ssh_keytypes_e;
                                  pkey: ssh_key): cint {.cdecl,
    importc: "ssh_pki_import_pubkey_base64", dynlib: libsshSONAME.}
proc ssh_pki_import_pubkey_file*(filename: cstring; pkey: ssh_key): cint {.cdecl,
    importc: "ssh_pki_import_pubkey_file", dynlib: libsshSONAME.}
proc ssh_pki_import_cert_base64*(b64_cert: cstring; `type`: ssh_keytypes_e;
                                pkey: ssh_key): cint {.cdecl,
    importc: "ssh_pki_import_cert_base64", dynlib: libsshSONAME.}
proc ssh_pki_import_cert_file*(filename: cstring; pkey: ssh_key): cint {.cdecl,
    importc: "ssh_pki_import_cert_file", dynlib: libsshSONAME.}
proc ssh_pki_export_privkey_to_pubkey*(privkey: ssh_key; pkey: ssh_key): cint {.
    cdecl, importc: "ssh_pki_export_privkey_to_pubkey", dynlib: libsshSONAME.}
proc ssh_pki_export_pubkey_base64*(key: ssh_key; b64_key: cstringArray): cint {.cdecl,
    importc: "ssh_pki_export_pubkey_base64", dynlib: libsshSONAME.}
proc ssh_pki_export_pubkey_file*(key: ssh_key; filename: cstring): cint {.cdecl,
    importc: "ssh_pki_export_pubkey_file", dynlib: libsshSONAME.}
proc ssh_pki_key_ecdsa_name*(key: ssh_key): cstring {.cdecl,
    importc: "ssh_pki_key_ecdsa_name", dynlib: libsshSONAME.}
proc ssh_get_fingerprint_hash*(`type`: ssh_publickey_hash_type; hash: cstring;
                              len: csize): cstring {.cdecl,
    importc: "ssh_get_fingerprint_hash", dynlib: libsshSONAME.}
proc ssh_print_hash*(`type`: ssh_publickey_hash_type; hash: cstring; len: csize) {.
    cdecl, importc: "ssh_print_hash", dynlib: libsshSONAME.}
proc ssh_send_ignore*(session: ssh_session; data: cstring): cint {.cdecl,
    importc: "ssh_send_ignore", dynlib: libsshSONAME.}
proc ssh_send_debug*(session: ssh_session; message: cstring; always_display: cint): cint {.
    cdecl, importc: "ssh_send_debug", dynlib: libsshSONAME.}
proc ssh_gssapi_set_creds*(session: ssh_session; creds: ssh_gssapi_creds) {.cdecl,
    importc: "ssh_gssapi_set_creds", dynlib: libsshSONAME.}
proc ssh_scp_accept_request*(scp: ssh_scp): cint {.cdecl,
    importc: "ssh_scp_accept_request", dynlib: libsshSONAME.}
proc ssh_scp_close*(scp: ssh_scp): cint {.cdecl, importc: "ssh_scp_close",
                                      dynlib: libsshSONAME.}
proc ssh_scp_deny_request*(scp: ssh_scp; reason: cstring): cint {.cdecl,
    importc: "ssh_scp_deny_request", dynlib: libsshSONAME.}
proc ssh_scp_free*(scp: ssh_scp) {.cdecl, importc: "ssh_scp_free",
                                dynlib: libsshSONAME.}
proc ssh_scp_init*(scp: ssh_scp): cint {.cdecl, importc: "ssh_scp_init",
                                     dynlib: libsshSONAME.}
proc ssh_scp_leave_directory*(scp: ssh_scp): cint {.cdecl,
    importc: "ssh_scp_leave_directory", dynlib: libsshSONAME.}
proc ssh_scp_new*(session: ssh_session; mode: cint; location: cstring): ssh_scp {.cdecl,
    importc: "ssh_scp_new", dynlib: libsshSONAME.}
proc ssh_scp_pull_request*(scp: ssh_scp): cint {.cdecl,
    importc: "ssh_scp_pull_request", dynlib: libsshSONAME.}
proc ssh_scp_push_directory*(scp: ssh_scp; dirname: cstring; mode: cint): cint {.cdecl,
    importc: "ssh_scp_push_directory", dynlib: libsshSONAME.}
proc ssh_scp_push_file*(scp: ssh_scp; filename: cstring; size: csize; perms: cint): cint {.
    cdecl, importc: "ssh_scp_push_file", dynlib: libsshSONAME.}
proc ssh_scp_push_file64*(scp: ssh_scp; filename: cstring; size: uint64; perms: cint): cint {.
    cdecl, importc: "ssh_scp_push_file64", dynlib: libsshSONAME.}
proc ssh_scp_read*(scp: ssh_scp; buffer: pointer; size: csize): cint {.cdecl,
    importc: "ssh_scp_read", dynlib: libsshSONAME.}
proc ssh_scp_request_get_filename*(scp: ssh_scp): cstring {.cdecl,
    importc: "ssh_scp_request_get_filename", dynlib: libsshSONAME.}
proc ssh_scp_request_get_permissions*(scp: ssh_scp): cint {.cdecl,
    importc: "ssh_scp_request_get_permissions", dynlib: libsshSONAME.}
proc ssh_scp_request_get_size*(scp: ssh_scp): csize {.cdecl,
    importc: "ssh_scp_request_get_size", dynlib: libsshSONAME.}
proc ssh_scp_request_get_size64*(scp: ssh_scp): uint64 {.cdecl,
    importc: "ssh_scp_request_get_size64", dynlib: libsshSONAME.}
proc ssh_scp_request_get_warning*(scp: ssh_scp): cstring {.cdecl,
    importc: "ssh_scp_request_get_warning", dynlib: libsshSONAME.}
proc ssh_scp_write*(scp: ssh_scp; buffer: pointer; len: csize): cint {.cdecl,
    importc: "ssh_scp_write", dynlib: libsshSONAME.}
proc ssh_select*(channels: ssh_channel; outchannels: ssh_channel;
                maxfd: socket_t; readfds: ptr fd_set; timeout: ptr timeval): cint {.
    cdecl, importc: "ssh_select", dynlib: libsshSONAME.}
proc ssh_service_request*(session: ssh_session; service: cstring): cint {.cdecl,
    importc: "ssh_service_request", dynlib: libsshSONAME.}
proc ssh_set_agent_channel*(session: ssh_session; channel: ssh_channel): cint {.cdecl,
    importc: "ssh_set_agent_channel", dynlib: libsshSONAME.}
proc ssh_set_agent_socket*(session: ssh_session; fd: socket_t): cint {.cdecl,
    importc: "ssh_set_agent_socket", dynlib: libsshSONAME.}
proc ssh_set_blocking*(session: ssh_session; blocking: cint) {.cdecl,
    importc: "ssh_set_blocking", dynlib: libsshSONAME.}
proc ssh_set_counters*(session: ssh_session; scounter: ssh_counter;
                      rcounter: ssh_counter) {.cdecl, importc: "ssh_set_counters",
    dynlib: libsshSONAME.}
proc ssh_set_fd_except*(session: ssh_session) {.cdecl, importc: "ssh_set_fd_except",
    dynlib: libsshSONAME.}
proc ssh_set_fd_toread*(session: ssh_session) {.cdecl, importc: "ssh_set_fd_toread",
    dynlib: libsshSONAME.}
proc ssh_set_fd_towrite*(session: ssh_session) {.cdecl,
    importc: "ssh_set_fd_towrite", dynlib: libsshSONAME.}
proc ssh_silent_disconnect*(session: ssh_session) {.cdecl,
    importc: "ssh_silent_disconnect", dynlib: libsshSONAME.}
proc ssh_set_pcap_file*(session: ssh_session; pcapfile: ssh_pcap_file): cint {.cdecl,
    importc: "ssh_set_pcap_file", dynlib: libsshSONAME.}
proc ssh_userauth_none*(session: ssh_session; username: cstring): cint {.cdecl,
    importc: "ssh_userauth_none", dynlib: libsshSONAME.}
proc ssh_userauth_list*(session: ssh_session; username: cstring): cint {.cdecl,
    importc: "ssh_userauth_list", dynlib: libsshSONAME.}
proc ssh_userauth_try_publickey*(session: ssh_session; username: cstring;
                                pubkey: ssh_key): cint {.cdecl,
    importc: "ssh_userauth_try_publickey", dynlib: libsshSONAME.}
proc ssh_userauth_publickey*(session: ssh_session; username: cstring;
                            privkey: ssh_key): cint {.cdecl,
    importc: "ssh_userauth_publickey", dynlib: libsshSONAME.}
proc ssh_userauth_agent*(session: ssh_session; username: cstring): cint {.cdecl,
    importc: "ssh_userauth_agent", dynlib: libsshSONAME.}
proc ssh_userauth_publickey_auto*(session: ssh_session; username: cstring;
                                 passphrase: cstring): cint {.cdecl,
    importc: "ssh_userauth_publickey_auto", dynlib: libsshSONAME.}
proc ssh_userauth_password*(session: ssh_session; username: cstring;
                           password: cstring): cint {.cdecl,
    importc: "ssh_userauth_password", dynlib: libsshSONAME.}
proc ssh_userauth_kbdint*(session: ssh_session; user: cstring; submethods: cstring): cint {.
    cdecl, importc: "ssh_userauth_kbdint", dynlib: libsshSONAME.}
proc ssh_userauth_kbdint_getinstruction*(session: ssh_session): cstring {.cdecl,
    importc: "ssh_userauth_kbdint_getinstruction", dynlib: libsshSONAME.}
proc ssh_userauth_kbdint_getname*(session: ssh_session): cstring {.cdecl,
    importc: "ssh_userauth_kbdint_getname", dynlib: libsshSONAME.}
proc ssh_userauth_kbdint_getnprompts*(session: ssh_session): cint {.cdecl,
    importc: "ssh_userauth_kbdint_getnprompts", dynlib: libsshSONAME.}
proc ssh_userauth_kbdint_getprompt*(session: ssh_session; i: cuint; echo: cstring): cstring {.
    cdecl, importc: "ssh_userauth_kbdint_getprompt", dynlib: libsshSONAME.}
proc ssh_userauth_kbdint_getnanswers*(session: ssh_session): cint {.cdecl,
    importc: "ssh_userauth_kbdint_getnanswers", dynlib: libsshSONAME.}
proc ssh_userauth_kbdint_getanswer*(session: ssh_session; i: cuint): cstring {.cdecl,
    importc: "ssh_userauth_kbdint_getanswer", dynlib: libsshSONAME.}
proc ssh_userauth_kbdint_setanswer*(session: ssh_session; i: cuint; answer: cstring): cint {.
    cdecl, importc: "ssh_userauth_kbdint_setanswer", dynlib: libsshSONAME.}
proc ssh_userauth_gssapi*(session: ssh_session): cint {.cdecl,
    importc: "ssh_userauth_gssapi", dynlib: libsshSONAME.}
proc ssh_version*(req_version: cint): cstring {.cdecl, importc: "ssh_version",
    dynlib: libsshSONAME.}
proc ssh_string_burn*(str: ssh_string) {.cdecl, importc: "ssh_string_burn",
                                      dynlib: libsshSONAME.}
proc ssh_string_copy*(str: ssh_string): ssh_string {.cdecl,
    importc: "ssh_string_copy", dynlib: libsshSONAME.}
proc ssh_string_data*(str: ssh_string): pointer {.cdecl, importc: "ssh_string_data",
    dynlib: libsshSONAME.}
proc ssh_string_fill*(str: ssh_string; data: pointer; len: csize): cint {.cdecl,
    importc: "ssh_string_fill", dynlib: libsshSONAME.}
template SSH_STRING_FREE*(x: untyped): void =
  while true:
    if (x) != nil:
      ssh_string_free(x)
      x = nil
    if not 0:
      break

proc ssh_string_free*(str: ssh_string) {.cdecl, importc: "ssh_string_free",
                                      dynlib: libsshSONAME.}
proc ssh_string_from_char*(what: cstring): ssh_string {.cdecl,
    importc: "ssh_string_from_char", dynlib: libsshSONAME.}
proc ssh_string_len*(str: ssh_string): csize {.cdecl, importc: "ssh_string_len",
    dynlib: libsshSONAME.}
proc ssh_string_new*(size: csize): ssh_string {.cdecl, importc: "ssh_string_new",
    dynlib: libsshSONAME.}
proc ssh_string_get_char*(str: ssh_string): cstring {.cdecl,
    importc: "ssh_string_get_char", dynlib: libsshSONAME.}
proc ssh_string_to_char*(str: ssh_string): cstring {.cdecl,
    importc: "ssh_string_to_char", dynlib: libsshSONAME.}
template SSH_STRING_FREE_CHAR*(x: untyped): void =
  while true:
    if (x) != nil:
      ssh_string_free_char(x)
      x = nil
    if not 0:
      break

proc ssh_string_free_char*(s: cstring) {.cdecl, importc: "ssh_string_free_char",
                                      dynlib: libsshSONAME.}
proc ssh_getpass*(prompt: cstring; buf: cstring; len: csize; echo: cint; verify: cint): cint {.
    cdecl, importc: "ssh_getpass", dynlib: libsshSONAME.}
type
  ssh_event_callback* = proc (fd: socket_t; revents: cint; userdata: pointer): cint {.
      cdecl.}

proc ssh_event_new*(): ssh_event {.cdecl, importc: "ssh_event_new",
                                dynlib: libsshSONAME.}
proc ssh_event_add_fd*(event: ssh_event; fd: socket_t; events: cshort;
                      cb: ssh_event_callback; userdata: pointer): cint {.cdecl,
    importc: "ssh_event_add_fd", dynlib: libsshSONAME.}
proc ssh_event_add_session*(event: ssh_event; session: ssh_session): cint {.cdecl,
    importc: "ssh_event_add_session", dynlib: libsshSONAME.}
proc ssh_event_add_connector*(event: ssh_event; connector: ssh_connector): cint {.
    cdecl, importc: "ssh_event_add_connector", dynlib: libsshSONAME.}
proc ssh_event_dopoll*(event: ssh_event; timeout: cint): cint {.cdecl,
    importc: "ssh_event_dopoll", dynlib: libsshSONAME.}
proc ssh_event_remove_fd*(event: ssh_event; fd: socket_t): cint {.cdecl,
    importc: "ssh_event_remove_fd", dynlib: libsshSONAME.}
proc ssh_event_remove_session*(event: ssh_event; session: ssh_session): cint {.cdecl,
    importc: "ssh_event_remove_session", dynlib: libsshSONAME.}
proc ssh_event_remove_connector*(event: ssh_event; connector: ssh_connector): cint {.
    cdecl, importc: "ssh_event_remove_connector", dynlib: libsshSONAME.}
proc ssh_event_free*(event: ssh_event) {.cdecl, importc: "ssh_event_free",
                                      dynlib: libsshSONAME.}
proc ssh_get_clientbanner*(session: ssh_session): cstring {.cdecl,
    importc: "ssh_get_clientbanner", dynlib: libsshSONAME.}
proc ssh_get_serverbanner*(session: ssh_session): cstring {.cdecl,
    importc: "ssh_get_serverbanner", dynlib: libsshSONAME.}
proc ssh_get_kex_algo*(session: ssh_session): cstring {.cdecl,
    importc: "ssh_get_kex_algo", dynlib: libsshSONAME.}
proc ssh_get_cipher_in*(session: ssh_session): cstring {.cdecl,
    importc: "ssh_get_cipher_in", dynlib: libsshSONAME.}
proc ssh_get_cipher_out*(session: ssh_session): cstring {.cdecl,
    importc: "ssh_get_cipher_out", dynlib: libsshSONAME.}
proc ssh_get_hmac_in*(session: ssh_session): cstring {.cdecl,
    importc: "ssh_get_hmac_in", dynlib: libsshSONAME.}
proc ssh_get_hmac_out*(session: ssh_session): cstring {.cdecl,
    importc: "ssh_get_hmac_out", dynlib: libsshSONAME.}
proc ssh_buffer_new*(): ssh_buffer {.cdecl, importc: "ssh_buffer_new",
                                  dynlib: libsshSONAME.}
proc ssh_buffer_free*(buffer: ssh_buffer) {.cdecl, importc: "ssh_buffer_free",
    dynlib: libsshSONAME.}
template SSH_BUFFER_FREE*(x: untyped): void =
  while true:
    if (x) != nil:
      ssh_buffer_free(x)
      x = nil
    if not 0:
      break

proc ssh_buffer_reinit*(buffer: ssh_buffer): cint {.cdecl,
    importc: "ssh_buffer_reinit", dynlib: libsshSONAME.}
proc ssh_buffer_add_data*(buffer: ssh_buffer; data: pointer; len: uint32): cint {.
    cdecl, importc: "ssh_buffer_add_data", dynlib: libsshSONAME.}
proc ssh_buffer_get_data*(buffer: ssh_buffer; data: pointer; requestedlen: uint32): uint32 {.
    cdecl, importc: "ssh_buffer_get_data", dynlib: libsshSONAME.}
proc ssh_buffer_get*(buffer: ssh_buffer): pointer {.cdecl, importc: "ssh_buffer_get",
    dynlib: libsshSONAME.}
proc ssh_buffer_get_len*(buffer: ssh_buffer): uint32 {.cdecl,
    importc: "ssh_buffer_get_len", dynlib: libsshSONAME.}
const
  SFTP_H* = true
  LIBSFTP_VERSION* = 3

type
  sftp_attributes* = ptr sftp_attributes_struct
  sftp_client_message* = ptr sftp_client_message_struct
  sftp_dir* = ptr sftp_dir_struct
  sftp_ext* = ptr sftp_ext_struct
  sftp_file* = ptr sftp_file_struct
  sftp_message* = ptr sftp_message_struct
  sftp_packet* = ptr sftp_packet_struct
  sftp_request_queue* = ptr sftp_request_queue_struct
  sftp_session* = ptr sftp_session_struct
  sftp_status_message* = ptr sftp_status_message_struct
  sftp_statvfs_t* = ptr sftp_statvfs_struct
  sftp_session_struct* {.bycopy.} = object
    session*: ssh_session
    channel*: ssh_channel
    server_version*: cint
    client_version*: cint
    version*: cint
    queue*: sftp_request_queue
    id_counter*: uint32
    errnum*: cint
    handles*: ptr pointer
    ext*: sftp_ext
    read_packet*: sftp_packet

  sftp_packet_struct* {.bycopy.} = object
    sftp*: sftp_session
    `type`*: uint8
    payload*: ssh_buffer

  sftp_file_struct* {.bycopy.} = object
    sftp*: sftp_session
    name*: cstring
    offset*: uint64
    handle*: ssh_string
    eof*: cint
    nonblocking*: cint

  sftp_dir_struct* {.bycopy.} = object
    sftp*: sftp_session
    name*: cstring
    handle*: ssh_string
    buffer*: ssh_buffer
    count*: uint32
    eof*: cint

  sftp_message_struct* {.bycopy.} = object
    sftp*: sftp_session
    packet_type*: uint8
    payload*: ssh_buffer
    id*: uint32

  sftp_client_message_struct* {.bycopy.} = object
    sftp*: sftp_session
    `type`*: uint8
    id*: uint32
    filename*: cstring
    flags*: uint32
    attr*: sftp_attributes
    handle*: ssh_string
    offset*: uint64
    len*: uint32
    attr_num*: cint
    attrbuf*: ssh_buffer
    data*: ssh_string
    complete_message*: ssh_buffer
    str_data*: cstring
    submessage*: cstring

  sftp_request_queue_struct* {.bycopy.} = object
    next*: sftp_request_queue
    message*: sftp_message

  sftp_status_message_struct* {.bycopy.} = object
    id*: uint32
    status*: uint32
    error_unused*: ssh_string
    lang_unused*: ssh_string
    errormsg*: cstring
    langmsg*: cstring

  sftp_attributes_struct* {.bycopy.} = object
    name*: cstring
    longname*: cstring
    flags*: uint32
    `type`*: uint8
    size*: uint64
    uid*: uint32
    gid*: uint32
    owner*: cstring
    group*: cstring
    permissions*: uint32
    atime64*: uint64
    atime*: uint32
    atime_nseconds*: uint32
    createtime*: uint64
    createtime_nseconds*: uint32
    mtime64*: uint64
    mtime*: uint32
    mtime_nseconds*: uint32
    acl*: ssh_string
    extended_count*: uint32
    extended_type*: ssh_string
    extended_data*: ssh_string

  sftp_statvfs_struct* {.bycopy.} = object
    f_bsize*: uint64
    f_frsize*: uint64
    f_blocks*: uint64
    f_bfree*: uint64
    f_bavail*: uint64
    f_files*: uint64
    f_ffree*: uint64
    f_favail*: uint64
    f_fsid*: uint64
    f_flag*: uint64
    f_namemax*: uint64


proc sftp_new*(session: ssh_session): sftp_session {.cdecl, importc: "sftp_new",
    dynlib: libsshSONAME.}
proc sftp_new_channel*(session: ssh_session; channel: ssh_channel): sftp_session {.
    cdecl, importc: "sftp_new_channel", dynlib: libsshSONAME.}
proc sftp_free*(sftp: sftp_session) {.cdecl, importc: "sftp_free",
                                   dynlib: libsshSONAME.}
proc sftp_init*(sftp: sftp_session): cint {.cdecl, importc: "sftp_init",
                                        dynlib: libsshSONAME.}
proc sftp_get_error*(sftp: sftp_session): cint {.cdecl, importc: "sftp_get_error",
    dynlib: libsshSONAME.}
proc sftp_extensions_get_count*(sftp: sftp_session): cuint {.cdecl,
    importc: "sftp_extensions_get_count", dynlib: libsshSONAME.}
proc sftp_extensions_get_name*(sftp: sftp_session; indexn: cuint): cstring {.cdecl,
    importc: "sftp_extensions_get_name", dynlib: libsshSONAME.}
proc sftp_extensions_get_data*(sftp: sftp_session; indexn: cuint): cstring {.cdecl,
    importc: "sftp_extensions_get_data", dynlib: libsshSONAME.}
proc sftp_extension_supported*(sftp: sftp_session; name: cstring; data: cstring): cint {.
    cdecl, importc: "sftp_extension_supported", dynlib: libsshSONAME.}
proc sftp_opendir*(session: sftp_session; path: cstring): sftp_dir {.cdecl,
    importc: "sftp_opendir", dynlib: libsshSONAME.}
proc sftp_readdir*(session: sftp_session; dir: sftp_dir): sftp_attributes {.cdecl,
    importc: "sftp_readdir", dynlib: libsshSONAME.}
proc sftp_dir_eof*(dir: sftp_dir): cint {.cdecl, importc: "sftp_dir_eof",
                                      dynlib: libsshSONAME.}
proc sftp_stat*(session: sftp_session; path: cstring): sftp_attributes {.cdecl,
    importc: "sftp_stat", dynlib: libsshSONAME.}
proc sftp_lstat*(session: sftp_session; path: cstring): sftp_attributes {.cdecl,
    importc: "sftp_lstat", dynlib: libsshSONAME.}
proc sftp_fstat*(file: sftp_file): sftp_attributes {.cdecl, importc: "sftp_fstat",
    dynlib: libsshSONAME.}
proc sftp_attributes_free*(file: sftp_attributes) {.cdecl,
    importc: "sftp_attributes_free", dynlib: libsshSONAME.}
proc sftp_closedir*(dir: sftp_dir): cint {.cdecl, importc: "sftp_closedir",
                                       dynlib: libsshSONAME.}
proc sftp_close*(file: sftp_file): cint {.cdecl, importc: "sftp_close",
                                      dynlib: libsshSONAME.}
proc sftp_open*(session: sftp_session; file: cstring; accesstype: cint; mode: mode_t): sftp_file {.
    cdecl, importc: "sftp_open", dynlib: libsshSONAME.}
proc sftp_file_set_nonblocking*(handle: sftp_file) {.cdecl,
    importc: "sftp_file_set_nonblocking", dynlib: libsshSONAME.}
proc sftp_file_set_blocking*(handle: sftp_file) {.cdecl,
    importc: "sftp_file_set_blocking", dynlib: libsshSONAME.}
proc sftp_read*(file: sftp_file; buf: pointer; count: csize): ssize_t {.cdecl,
    importc: "sftp_read", dynlib: libsshSONAME.}
proc sftp_async_read_begin*(file: sftp_file; len: uint32): cint {.cdecl,
    importc: "sftp_async_read_begin", dynlib: libsshSONAME.}
proc sftp_async_read*(file: sftp_file; data: pointer; len: uint32; id: uint32): cint {.
    cdecl, importc: "sftp_async_read", dynlib: libsshSONAME.}
proc sftp_write*(file: sftp_file; buf: pointer; count: csize): ssize_t {.cdecl,
    importc: "sftp_write", dynlib: libsshSONAME.}
proc sftp_seek*(file: sftp_file; new_offset: uint32): cint {.cdecl,
    importc: "sftp_seek", dynlib: libsshSONAME.}
proc sftp_seek64*(file: sftp_file; new_offset: uint64): cint {.cdecl,
    importc: "sftp_seek64", dynlib: libsshSONAME.}
proc sftp_tell*(file: sftp_file): culong {.cdecl, importc: "sftp_tell",
                                       dynlib: libsshSONAME.}
proc sftp_tell64*(file: sftp_file): uint64 {.cdecl, importc: "sftp_tell64",
    dynlib: libsshSONAME.}
proc sftp_rewind*(file: sftp_file) {.cdecl, importc: "sftp_rewind",
                                  dynlib: libsshSONAME.}
proc sftp_unlink*(sftp: sftp_session; file: cstring): cint {.cdecl,
    importc: "sftp_unlink", dynlib: libsshSONAME.}
proc sftp_rmdir*(sftp: sftp_session; directory: cstring): cint {.cdecl,
    importc: "sftp_rmdir", dynlib: libsshSONAME.}
proc sftp_mkdir*(sftp: sftp_session; directory: cstring; mode: mode_t): cint {.cdecl,
    importc: "sftp_mkdir", dynlib: libsshSONAME.}
proc sftp_rename*(sftp: sftp_session; original: cstring; newname: cstring): cint {.
    cdecl, importc: "sftp_rename", dynlib: libsshSONAME.}
proc sftp_setstat*(sftp: sftp_session; file: cstring; attr: sftp_attributes): cint {.
    cdecl, importc: "sftp_setstat", dynlib: libsshSONAME.}
proc sftp_chown*(sftp: sftp_session; file: cstring; owner: uid_t; group: gid_t): cint {.
    cdecl, importc: "sftp_chown", dynlib: libsshSONAME.}
proc sftp_chmod*(sftp: sftp_session; file: cstring; mode: mode_t): cint {.cdecl,
    importc: "sftp_chmod", dynlib: libsshSONAME.}
proc sftp_utimes*(sftp: sftp_session; file: cstring; times: ptr timeval): cint {.cdecl,
    importc: "sftp_utimes", dynlib: libsshSONAME.}
proc sftp_symlink*(sftp: sftp_session; target: cstring; dest: cstring): cint {.cdecl,
    importc: "sftp_symlink", dynlib: libsshSONAME.}
proc sftp_readlink*(sftp: sftp_session; path: cstring): cstring {.cdecl,
    importc: "sftp_readlink", dynlib: libsshSONAME.}
proc sftp_statvfs*(sftp: sftp_session; path: cstring): sftp_statvfs_t {.cdecl,
    importc: "sftp_statvfs", dynlib: libsshSONAME.}
proc sftp_fstatvfs*(file: sftp_file): sftp_statvfs_t {.cdecl,
    importc: "sftp_fstatvfs", dynlib: libsshSONAME.}
proc sftp_statvfs_free*(statvfs_o: sftp_statvfs_t) {.cdecl,
    importc: "sftp_statvfs_free", dynlib: libsshSONAME.}
proc sftp_fsync*(file: sftp_file): cint {.cdecl, importc: "sftp_fsync",
                                      dynlib: libsshSONAME.}
proc sftp_canonicalize_path*(sftp: sftp_session; path: cstring): cstring {.cdecl,
    importc: "sftp_canonicalize_path", dynlib: libsshSONAME.}
proc sftp_server_version*(sftp: sftp_session): cint {.cdecl,
    importc: "sftp_server_version", dynlib: libsshSONAME.}
const
  SFTP_HANDLES* = 256

proc sftp_packet_read*(sftp: sftp_session): sftp_packet {.cdecl,
    importc: "sftp_packet_read", dynlib: libsshSONAME.}
proc sftp_packet_write*(sftp: sftp_session; `type`: uint8; payload: ssh_buffer): cint {.
    cdecl, importc: "sftp_packet_write", dynlib: libsshSONAME.}
proc sftp_packet_free*(packet: sftp_packet) {.cdecl, importc: "sftp_packet_free",
    dynlib: libsshSONAME.}
proc buffer_add_attributes*(buffer: ssh_buffer; attr: sftp_attributes): cint {.cdecl,
    importc: "buffer_add_attributes", dynlib: libsshSONAME.}
proc sftp_parse_attr*(session: sftp_session; buf: ssh_buffer; expectname: cint): sftp_attributes {.
    cdecl, importc: "sftp_parse_attr", dynlib: libsshSONAME.}
proc sftp_get_client_message*(sftp: sftp_session): sftp_client_message {.cdecl,
    importc: "sftp_get_client_message", dynlib: libsshSONAME.}
proc sftp_client_message_free*(msg: sftp_client_message) {.cdecl,
    importc: "sftp_client_message_free", dynlib: libsshSONAME.}
proc sftp_client_message_get_type*(msg: sftp_client_message): uint8 {.cdecl,
    importc: "sftp_client_message_get_type", dynlib: libsshSONAME.}
proc sftp_client_message_get_filename*(msg: sftp_client_message): cstring {.cdecl,
    importc: "sftp_client_message_get_filename", dynlib: libsshSONAME.}
proc sftp_client_message_set_filename*(msg: sftp_client_message; newname: cstring) {.
    cdecl, importc: "sftp_client_message_set_filename", dynlib: libsshSONAME.}
proc sftp_client_message_get_data*(msg: sftp_client_message): cstring {.cdecl,
    importc: "sftp_client_message_get_data", dynlib: libsshSONAME.}
proc sftp_client_message_get_flags*(msg: sftp_client_message): uint32 {.cdecl,
    importc: "sftp_client_message_get_flags", dynlib: libsshSONAME.}
proc sftp_client_message_get_submessage*(msg: sftp_client_message): cstring {.cdecl,
    importc: "sftp_client_message_get_submessage", dynlib: libsshSONAME.}
proc sftp_send_client_message*(sftp: sftp_session; msg: sftp_client_message): cint {.
    cdecl, importc: "sftp_send_client_message", dynlib: libsshSONAME.}
proc sftp_reply_name*(msg: sftp_client_message; name: cstring; attr: sftp_attributes): cint {.
    cdecl, importc: "sftp_reply_name", dynlib: libsshSONAME.}
proc sftp_reply_handle*(msg: sftp_client_message; handle: ssh_string): cint {.cdecl,
    importc: "sftp_reply_handle", dynlib: libsshSONAME.}
proc sftp_handle_alloc*(sftp: sftp_session; info: pointer): ssh_string {.cdecl,
    importc: "sftp_handle_alloc", dynlib: libsshSONAME.}
proc sftp_reply_attr*(msg: sftp_client_message; attr: sftp_attributes): cint {.cdecl,
    importc: "sftp_reply_attr", dynlib: libsshSONAME.}
proc sftp_handle*(sftp: sftp_session; handle: ssh_string): pointer {.cdecl,
    importc: "sftp_handle", dynlib: libsshSONAME.}
proc sftp_reply_status*(msg: sftp_client_message; status: uint32; message: cstring): cint {.
    cdecl, importc: "sftp_reply_status", dynlib: libsshSONAME.}
proc sftp_reply_names_add*(msg: sftp_client_message; file: cstring;
                          longname: cstring; attr: sftp_attributes): cint {.cdecl,
    importc: "sftp_reply_names_add", dynlib: libsshSONAME.}
proc sftp_reply_names*(msg: sftp_client_message): cint {.cdecl,
    importc: "sftp_reply_names", dynlib: libsshSONAME.}
proc sftp_reply_data*(msg: sftp_client_message; data: pointer; len: cint): cint {.cdecl,
    importc: "sftp_reply_data", dynlib: libsshSONAME.}
proc sftp_handle_remove*(sftp: sftp_session; handle: pointer) {.cdecl,
    importc: "sftp_handle_remove", dynlib: libsshSONAME.}
const
  SSH_FXP_INIT* = 1
  SSH_FXP_VERSION* = 2
  SSH_FXP_OPEN* = 3
  SSH_FXP_CLOSE* = 4
  SSH_FXP_READ* = 5
  SSH_FXP_WRITE* = 6
  SSH_FXP_LSTAT* = 7
  SSH_FXP_FSTAT* = 8
  SSH_FXP_SETSTAT* = 9
  SSH_FXP_FSETSTAT* = 10
  SSH_FXP_OPENDIR* = 11
  SSH_FXP_READDIR* = 12
  SSH_FXP_REMOVE* = 13
  SSH_FXP_MKDIR* = 14
  SSH_FXP_RMDIR* = 15
  SSH_FXP_REALPATH* = 16
  SSH_FXP_STAT* = 17
  SSH_FXP_RENAME* = 18
  SSH_FXP_READLINK* = 19
  SSH_FXP_SYMLINK* = 20
  SSH_FXP_STATUS* = 101
  SSH_FXP_HANDLE* = 102
  SSH_FXP_DATA* = 103
  SSH_FXP_NAME* = 104
  SSH_FXP_ATTRS* = 105
  SSH_FXP_EXTENDED* = 200
  SSH_FXP_EXTENDED_REPLY* = 201
  SSH_FILEXFER_ATTR_SIZE* = 0x00000001
  SSH_FILEXFER_ATTR_PERMISSIONS* = 0x00000004
  SSH_FILEXFER_ATTR_ACCESSTIME* = 0x00000008
  SSH_FILEXFER_ATTR_ACMODTIME* = 0x00000008
  SSH_FILEXFER_ATTR_CREATETIME* = 0x00000010
  SSH_FILEXFER_ATTR_MODIFYTIME* = 0x00000020
  SSH_FILEXFER_ATTR_ACL* = 0x00000040
  SSH_FILEXFER_ATTR_OWNERGROUP* = 0x00000080
  SSH_FILEXFER_ATTR_SUBSECOND_TIMES* = 0x00000100
  SSH_FILEXFER_ATTR_EXTENDED* = 0x80000000
  SSH_FILEXFER_ATTR_UIDGID* = 0x00000002
  SSH_FILEXFER_TYPE_REGULAR* = 1
  SSH_FILEXFER_TYPE_DIRECTORY* = 2
  SSH_FILEXFER_TYPE_SYMLINK* = 3
  SSH_FILEXFER_TYPE_SPECIAL* = 4
  SSH_FILEXFER_TYPE_UNKNOWN* = 5
  SSH_FX_OK* = 0
  SSH_FX_EOF* = 1
  SSH_FX_NO_SUCH_FILE* = 2
  SSH_FX_PERMISSION_DENIED* = 3
  SSH_FX_FAILURE* = 4
  SSH_FX_BAD_MESSAGE* = 5
  SSH_FX_NO_CONNECTION* = 6
  SSH_FX_CONNECTION_LOST* = 7
  SSH_FX_OP_UNSUPPORTED* = 8
  SSH_FX_INVALID_HANDLE* = 9
  SSH_FX_NO_SUCH_PATH* = 10
  SSH_FX_FILE_ALREADY_EXISTS* = 11
  SSH_FX_WRITE_PROTECT* = 12
  SSH_FX_NO_MEDIA* = 13
  SSH_FXF_READ* = 0x00000001
  SSH_FXF_WRITE* = 0x00000002
  SSH_FXF_APPEND* = 0x00000004
  SSH_FXF_CREAT* = 0x00000008
  SSH_FXF_TRUNC* = 0x00000010
  SSH_FXF_EXCL* = 0x00000020
  SSH_FXF_TEXT* = 0x00000040
  SSH_S_IFMT* = 170000
  SSH_S_IFSOCK* = 0o000000140000
  SSH_S_IFLNK* = 0o000000120000
  SSH_S_IFREG* = 0o000000100000
  SSH_S_IFBLK* = 60000
  SSH_S_IFDIR* = 40000
  SSH_S_IFCHR* = 20000
  SSH_S_IFIFO* = 10000
  SSH_FXF_RENAME_OVERWRITE* = 0x00000001
  SSH_FXF_RENAME_ATOMIC* = 0x00000002
  SSH_FXF_RENAME_NATIVE* = 0x00000004
  SFTP_OPEN* = SSH_FXP_OPEN
  SFTP_CLOSE* = SSH_FXP_CLOSE
  SFTP_READ* = SSH_FXP_READ
  SFTP_WRITE* = SSH_FXP_WRITE
  SFTP_LSTAT* = SSH_FXP_LSTAT
  SFTP_FSTAT* = SSH_FXP_FSTAT
  SFTP_SETSTAT* = SSH_FXP_SETSTAT
  SFTP_FSETSTAT* = SSH_FXP_FSETSTAT
  SFTP_OPENDIR* = SSH_FXP_OPENDIR
  SFTP_READDIR* = SSH_FXP_READDIR
  SFTP_REMOVE* = SSH_FXP_REMOVE
  SFTP_MKDIR* = SSH_FXP_MKDIR
  SFTP_RMDIR* = SSH_FXP_RMDIR
  SFTP_REALPATH* = SSH_FXP_REALPATH
  SFTP_STAT* = SSH_FXP_STAT
  SFTP_RENAME* = SSH_FXP_RENAME
  SFTP_READLINK* = SSH_FXP_READLINK
  SFTP_SYMLINK* = SSH_FXP_SYMLINK
  SFTP_EXTENDED* = SSH_FXP_EXTENDED
  SSH_FXE_STATVFS_ST_RDONLY* = 0x00000001
  SSH_FXE_STATVFS_ST_NOSUID* = 0x00000002
  SSH2_MSG_DISCONNECT* = 1
  SSH2_MSG_IGNORE* = 2
  SSH2_MSG_UNIMPLEMENTED* = 3
  SSH2_MSG_DEBUG* = 4
  SSH2_MSG_SERVICE_REQUEST* = 5
  SSH2_MSG_SERVICE_ACCEPT* = 6
  SSH2_MSG_EXT_INFO* = 7
  SSH2_MSG_KEXINIT* = 20
  SSH2_MSG_NEWKEYS* = 21
  SSH2_MSG_KEXDH_INIT* = 30
  SSH2_MSG_KEXDH_REPLY* = 31
  SSH2_MSG_KEX_ECDH_INIT* = 30
  SSH2_MSG_KEX_ECDH_REPLY* = 31
  SSH2_MSG_ECMQV_INIT* = 30
  SSH2_MSG_ECMQV_REPLY* = 31
  SSH2_MSG_KEX_DH_GEX_REQUEST_OLD* = 30
  SSH2_MSG_KEX_DH_GEX_GROUP* = 31
  SSH2_MSG_KEX_DH_GEX_INIT* = 32
  SSH2_MSG_KEX_DH_GEX_REPLY* = 33
  SSH2_MSG_KEX_DH_GEX_REQUEST* = 34
  SSH2_MSG_USERAUTH_REQUEST* = 50
  SSH2_MSG_USERAUTH_FAILURE* = 51
  SSH2_MSG_USERAUTH_SUCCESS* = 52
  SSH2_MSG_USERAUTH_BANNER* = 53
  SSH2_MSG_USERAUTH_PK_OK* = 60
  SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ* = 60
  SSH2_MSG_USERAUTH_INFO_REQUEST* = 60
  SSH2_MSG_USERAUTH_GSSAPI_RESPONSE* = 60
  SSH2_MSG_USERAUTH_INFO_RESPONSE* = 61
  SSH2_MSG_USERAUTH_GSSAPI_TOKEN* = 61
  SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE* = 63
  SSH2_MSG_USERAUTH_GSSAPI_ERROR* = 64
  SSH2_MSG_USERAUTH_GSSAPI_ERRTOK* = 65
  SSH2_MSG_USERAUTH_GSSAPI_MIC* = 66
  SSH2_MSG_GLOBAL_REQUEST* = 80
  SSH2_MSG_REQUEST_SUCCESS* = 81
  SSH2_MSG_REQUEST_FAILURE* = 82
  SSH2_MSG_CHANNEL_OPEN* = 90
  SSH2_MSG_CHANNEL_OPEN_CONFIRMATION* = 91
  SSH2_MSG_CHANNEL_OPEN_FAILURE* = 92
  SSH2_MSG_CHANNEL_WINDOW_ADJUST* = 93
  SSH2_MSG_CHANNEL_DATA* = 94
  SSH2_MSG_CHANNEL_EXTENDED_DATA* = 95
  SSH2_MSG_CHANNEL_EOF* = 96
  SSH2_MSG_CHANNEL_CLOSE* = 97
  SSH2_MSG_CHANNEL_REQUEST* = 98
  SSH2_MSG_CHANNEL_SUCCESS* = 99
  SSH2_MSG_CHANNEL_FAILURE* = 100
  SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT* = 1
  SSH2_DISCONNECT_PROTOCOL_ERROR* = 2
  SSH2_DISCONNECT_KEY_EXCHANGE_FAILED* = 3
  SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED* = 4
  SSH2_DISCONNECT_RESERVED* = 4
  SSH2_DISCONNECT_MAC_ERROR* = 5
  SSH2_DISCONNECT_COMPRESSION_ERROR* = 6
  SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE* = 7
  SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED* = 8
  SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE* = 9
  SSH2_DISCONNECT_CONNECTION_LOST* = 10
  SSH2_DISCONNECT_BY_APPLICATION* = 11
  SSH2_DISCONNECT_TOO_MANY_CONNECTIONS* = 12
  SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER* = 13
  SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE* = 14
  SSH2_DISCONNECT_ILLEGAL_USER_NAME* = 15
  SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED* = 1
  SSH2_OPEN_CONNECT_FAILED* = 2
  SSH2_OPEN_UNKNOWN_CHANNEL_TYPE* = 3
  SSH2_OPEN_RESOURCE_SHORTAGE* = 4
  SSH2_EXTENDED_DATA_STDERR* = 1
