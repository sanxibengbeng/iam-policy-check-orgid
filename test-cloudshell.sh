#!/bin/bash

# 测试CloudShell兼容性的简化版本

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== CloudShell兼容性测试 ===${NC}"

# 创建logs目录
LOGS_DIR="logs"
mkdir -p "$LOGS_DIR"

# 日志文件
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_FILE="$LOGS_DIR/test-$TIMESTAMP.log"

echo "测试开始 - $(date)" > "$LOG_FILE"

# 测试基本AWS命令
echo -e "${YELLOW}1. 测试AWS CLI基本功能${NC}"
if aws sts get-caller-identity > /dev/null 2>&1; then
    echo -e "${GREEN}✓ AWS CLI工作正常${NC}"
    echo "AWS CLI工作正常" >> "$LOG_FILE"
else
    echo -e "${RED}✗ AWS CLI无法工作${NC}"
    echo "AWS CLI无法工作" >> "$LOG_FILE"
    exit 1
fi

# 测试IAM列表命令
echo -e "${YELLOW}2. 测试IAM角色列表${NC}"
echo "获取IAM角色列表..."

# 方法1: 直接命令
echo "方法1: 直接AWS命令"
if aws iam list-roles --query 'Roles[0:3].RoleName' --output text 2>/dev/null; then
    echo -e "${GREEN}✓ 直接命令成功${NC}"
else
    echo -e "${RED}✗ 直接命令失败${NC}"
fi

# 方法2: 使用临时文件
echo "方法2: 使用临时文件"
temp_file=$(mktemp)
if aws iam list-roles --query 'Roles[0:3].RoleName' --output text > "$temp_file" 2>/dev/null; then
    echo -e "${GREEN}✓ 临时文件方法成功${NC}"
    echo "前3个角色:"
    cat "$temp_file"
    rm -f "$temp_file"
else
    echo -e "${RED}✗ 临时文件方法失败${NC}"
    rm -f "$temp_file"
fi

# 方法3: 使用数组
echo "方法3: 使用数组"
roles_array=()
while IFS= read -r role; do
    if [ -n "$role" ] && [ "$role" != "None" ]; then
        roles_array+=("$role")
    fi
done < <(aws iam list-roles --query 'Roles[0:3].RoleName' --output text 2>/dev/null | tr '\t' '\n')

if [ ${#roles_array[@]} -gt 0 ]; then
    echo -e "${GREEN}✓ 数组方法成功，找到 ${#roles_array[@]} 个角色${NC}"
    for role in "${roles_array[@]}"; do
        echo "  - $role"
    done
else
    echo -e "${RED}✗ 数组方法失败${NC}"
fi

# 测试jq
echo -e "${YELLOW}3. 测试jq工具${NC}"
if command -v jq > /dev/null 2>&1; then
    echo -e "${GREEN}✓ jq可用${NC}"
    echo '{"test": "value"}' | jq .
else
    echo -e "${RED}✗ jq不可用${NC}"
fi

echo -e "${GREEN}测试完成${NC}"
echo "测试完成 - $(date)" >> "$LOG_FILE"
echo "日志文件: $LOG_FILE"
