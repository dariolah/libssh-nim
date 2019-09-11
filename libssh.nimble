# Package

version       = "0.90.0"
author        = "Dario Lah"
description   = "libssh FFI bindings"
license       = "MIT"


# Dependencies

requires "nim >= 0.20.2"

when defined(nimdistros):
  import distros
  if detectOs(Linux):
    foreignDep "libssh.so"

  elif detectOs(Windows):
    foreignDep "ssh.dll"
  else:
    foreignDep "libssh.dylib"
