#!/bin/bash

# AWS账号组织策略检查工具 - 环境设置脚本

echo "🚀 设置AWS账号组织策略检查工具环境..."

# 检查Python3
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 未安装，请先安装Python3"
    exit 1
fi

echo "✅ Python3 已安装: $(python3 --version)"

# 检查pip3
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 未安装，请先安装pip3"
    exit 1
fi

echo "✅ pip3 已安装"

# 创建虚拟环境并安装boto3
echo "📦 创建Python虚拟环境..."
python3 -m venv venv

echo "📦 激活虚拟环境并安装boto3..."
source venv/bin/activate
pip install boto3
deactivate

# 检查AWS CLI
if ! command -v aws &> /dev/null; then
    echo "⚠️  AWS CLI 未安装，建议安装以使用Bash版本的脚本"
    echo "   安装方法: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
else
    echo "✅ AWS CLI 已安装: $(aws --version)"
fi

# 检查jq
if ! command -v jq &> /dev/null; then
    echo "⚠️  jq 未安装，建议安装以使用Bash版本的脚本"
    echo "   macOS安装: brew install jq"
    echo "   Ubuntu安装: sudo apt-get install jq"
else
    echo "✅ jq 已安装: $(jq --version)"
fi

# 给脚本添加执行权限
chmod +x check-org-policies.sh
chmod +x check_org_policies.py

echo ""
echo "🎉 环境设置完成！"
echo ""
echo "使用方法："
echo "1. Python版本 (推荐):"
echo "   python3 check_org_policies.py"
echo "   python3 check_org_policies.py --profile my-profile --region us-west-2"
echo ""
echo "2. Bash版本:"
echo "   ./check-org-policies.sh"
echo ""
echo "注意：请确保已配置AWS凭证 (aws configure 或 ~/.aws/credentials)"
