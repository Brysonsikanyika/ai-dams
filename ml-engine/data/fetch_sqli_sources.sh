#!/bin/bash
# Clones the public sources used to build the v2 SQL-injection dataset into ./external
# (about 150 MB). They are third-party data: keep ./external out of git.
# Retries, and forces HTTP/1.1 for these clones only (no global git config is changed),
# because long clones over HTTP/2 sometimes die with "stream reset".
set -e
mkdir -p external && cd external

clone() {   # clone <dir> <url> <path that must exist afterwards> [sparse-checkout path]
  local dir=$1 url=$2 must=$3 sparse=$4
  if [ -e "$dir/$must" ]; then echo "have $dir"; return 0; fi
  for attempt in 1 2 3 4 5; do
    rm -rf "$dir"
    if [ -n "$sparse" ]; then
      git -c http.version=HTTP/1.1 clone --depth 1 --filter=blob:none --sparse -q "$url" "$dir" \
        && (cd "$dir" && git -c http.version=HTTP/1.1 sparse-checkout set "$sparse") \
        && [ -e "$dir/$must" ] && { echo "cloned $dir"; return 0; }
    else
      git -c http.version=HTTP/1.1 clone --depth 1 -q "$url" "$dir" \
        && [ -e "$dir/$must" ] && { echo "cloned $dir"; return 0; }
    fi
    echo "clone of $dir failed (attempt $attempt of 5), retrying..."; sleep 3
  done
  echo "giving up on $dir -- check your connection and run this script again"; exit 1
}

clone text2sql-data       https://github.com/jkkummerfeld/text2sql-data.git          data
clone WikiSQL             https://github.com/salesforce/WikiSQL.git                  data.tar.bz2
clone SecLists            https://github.com/danielmiessler/SecLists.git             Fuzzing/Databases/SQLi  "Fuzzing/Databases/SQLi"
clone PayloadsAllTheThings https://github.com/swisskyrepo/PayloadsAllTheThings.git   "SQL Injection/Intruder" "SQL Injection"
echo "sources ready in $(pwd)"
