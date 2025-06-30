#!/bin/bash

# AWS账号组织策略检查工具 - 运行脚本

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 检查虚拟环境是否存在
if [ ! -d "$SCRIPT_DIR/venv" ]; then
    echo "❌ 虚拟环境不存在，请先运行 ./setup.sh"
    exit 1
fi

# 激活虚拟环境并运行Python脚本
echo "🚀 激活虚拟环境并运行检查..."
source "$SCRIPT_DIR/venv/bin/activate"
python3 "$SCRIPT_DIR/check_org_policies.py" "$@"
deactivate
