#!/bin/bash

HEADERS=(libssh.h \
             sftp.h \
             ssh2.h)

rm -f libssh_concat.h

for h in "${HEADERS[@]}"
do
    ./prepare.sh ~/.local/include/libssh/$h >> libssh_concat.h
done

sed -i -E '/.#/d;
    /#define _LIBSSH_H/d;
    /#define LIBSSH_API/d;
    /#define PRINTF_ATTRIBUTE/d;
    /#define SSH_DEPRECATED/d;
    s/^SSH_DEPRECATED //;
    s/^LIBSSH_API //;
    s/ _ssh/ x_ssh/;
    s/ PRINTF_ATTRIBUTE.*/;/;
    /SSH_INVALID_SOCKET/d;
' libssh_concat.h

c2nim --dynlib:libsshSONAME --cdecl libssh_concat.h

sed -i -E 's/SSH_VERSION_DOT.*$/$a \& "." \& $b \& "." \& $c/;
    s/uint64_t/uint64/g;
    s/uint32_t/uint32/g;
    s/uint8_t/uint8/g;
    s/(ssh_.*\* = ptr) ssh_.*/\1 object/;
    s/ptr ssh_/ssh_/g;
    s/ptr ptr cuchar/ptr cstring/;
    s/ptr cuchar/cstring/;
    ' libssh_concat.nim

cat << 'EOF' > libssh.nim
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

EOF

cat libssh_concat.nim >> libssh.nim
rm libssh_concat.*
