#!/bin/bash
set -e

echo "=== Guard Proxy DevContainer Setup ==="

# Install dependencies
uv sync

# Configure npm to use guard-proxy
cat > ~/.npmrc << 'EOF'
registry=http://localhost:4873/
EOF

# Configure pip to use guard-proxy
mkdir -p ~/.config/pip
cat > ~/.config/pip/pip.conf << 'EOF'
[global]
index-url = http://localhost:4874/simple/
trusted-host = localhost
EOF

# Configure gem/bundler to use guard-proxy
cat > ~/.gemrc << 'EOF'
---
:sources:
- http://localhost:4875/
EOF

# Configure Go to use guard-proxy
echo 'export GOPROXY=http://localhost:4876,direct' >> ~/.bashrc
echo 'export GONOSUMCHECK=*' >> ~/.bashrc

echo ""
echo "=== Setup Complete ==="
echo "Run 'uv run guard-proxy start' to start the proxy."
echo "Package managers are pre-configured to route through Guard Proxy."
echo ""
echo "Ports:"
echo "  npm:      http://localhost:4873"
echo "  PyPI:     http://localhost:4874"
echo "  RubyGems: http://localhost:4875"
echo "  Go:       http://localhost:4876"
echo "  Admin:    http://localhost:8100"
