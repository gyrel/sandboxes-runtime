#!/bin/sh
# Reject a libkrunfw ARM64 kernel config that cannot run Docker's netfilter
# bridge and NAT rules. The guest bundles only the kernel Image, so every
# required symbol must be built in (=y), not modular or disabled.
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: verify-libkrunfw-netfilter-config.sh CONFIG" >&2
  exit 2
fi

config=$1
test -f "$config" || { echo "kernel config not found: $config" >&2; exit 1; }
test -r "$config" || { echo "kernel config is not readable: $config" >&2; exit 1; }

check_builtin() {
  symbol=$1
  count=$(grep -c "^$symbol=" "$config" || true)
  if [ "$count" -ne 1 ]; then
    echo "kernel config must define $symbol exactly once; found $count definitions" >&2
    exit 1
  fi
  if ! grep -Fqx "$symbol=y" "$config"; then
    echo "kernel config must build in $symbol=y" >&2
    exit 1
  fi
  if grep -Fqx "# $symbol is not set" "$config"; then
    echo "kernel config disables required symbol $symbol" >&2
    exit 1
  fi
}

# Existing prerequisites for Docker's iptables/nftables bridge networking and
# source NAT. Checking them here also catches a patch that accidentally
# replaces or relaxes the pinned kernel configuration.
for symbol in \
  CONFIG_NETFILTER \
  CONFIG_NF_CONNTRACK \
  CONFIG_NF_NAT \
  CONFIG_NF_NAT_MASQUERADE \
  CONFIG_NF_TABLES \
  CONFIG_NF_TABLES_IPV4 \
  CONFIG_NFT_NAT \
  CONFIG_NETFILTER_XTABLES \
  CONFIG_NFT_COMPAT \
  CONFIG_NETFILTER_XT_MATCH_ADDRTYPE \
  CONFIG_NETFILTER_XT_MATCH_CONNTRACK \
  CONFIG_NETFILTER_XT_TARGET_MASQUERADE
do
  check_builtin "$symbol"
done
