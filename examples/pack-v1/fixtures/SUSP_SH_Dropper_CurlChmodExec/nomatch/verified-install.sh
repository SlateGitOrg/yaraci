#!/bin/sh
# yaraci lab fixture - synthetic and benign: downloads a checksum file, verifies, never executes from /tmp
curl -fsSL https://releases.example.invalid/tool.tar.gz -o /tmp/tool.tar.gz
sha256sum -c tool.tar.gz.sha256 && tar -xzf /tmp/tool.tar.gz -C "$HOME/.local"
