#!/bin/sh
# Shared helper: load OmniSec config into the environment (auto-exported).
# Sourced by every omnisec-*-run launcher. Works on Linux and macOS by
# checking both standard config locations.
set -a
for _f in /etc/omnisec/omnisec.env /usr/local/etc/omnisec/omnisec.env; do
    [ -f "$_f" ] && . "$_f"
done
set +a
