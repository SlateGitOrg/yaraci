#!/bin/sh
# yaraci lab fixture - synthetic and benign: the usual 'curl | sh' installer one-liner from a README
set -eu
echo 'Installing exampletool'
curl -fsSL https://sh.example.invalid/install.sh | sh -s -- --yes
