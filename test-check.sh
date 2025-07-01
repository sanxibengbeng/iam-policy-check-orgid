#!/bin/bash

# 测试脚本 - 验证检查工具的基本功能

echo "🧪 测试AWS组织策略检查工具..."

# 检查必要的命令是否存在
echo "检查依赖..."

if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI 未安装"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "❌ jq 未安装"
    exit 1
fi

echo "✅ 依赖检查通过"

# 检查AWS凭证
echo "检查AWS凭证..."
if ! aws sts get-caller-identity &> /dev/null; then
    echo "❌ AWS凭证未配置或无效"
    echo "请运行 'aws configure' 配置AWS凭证"
    exit 1
fi

echo "✅ AWS凭证有效"

# 显示当前AWS身份
echo "当前AWS身份:"
aws sts get-caller-identity --output table

echo ""
echo "🚀 准备运行检查工具..."
echo "注意：这将检查当前AWS账号中的所有策略配置"
echo ""

read -p "是否继续运行检查？(y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "开始运行检查..."
    ./check-org-policies.sh
else
    echo "检查已取消"
fi
