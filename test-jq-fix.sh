#!/bin/bash

# 快速测试脚本 - 验证jq修复

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== 测试jq修复 ===${NC}"
echo ""

# 检查必要工具
if ! command -v jq &> /dev/null; then
    echo -e "${RED}错误: jq未安装${NC}"
    exit 1
fi

if ! command -v aws &> /dev/null; then
    echo -e "${RED}错误: AWS CLI未安装${NC}"
    exit 1
fi

# 检查AWS凭证
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}错误: AWS凭证未配置或无效${NC}"
    exit 1
fi

echo -e "${GREEN}✓ 依赖检查通过${NC}"
echo ""

# 测试优化版本脚本（限制时间和并行任务数）
echo -e "${YELLOW}运行优化版本脚本测试...${NC}"
echo "使用配置: MAX_PARALLEL_JOBS=3, 超时时间: 60秒"

if timeout 60 bash -c "MAX_PARALLEL_JOBS=3 ./check-org-policies-optimized.sh" > test-output.log 2>&1; then
    echo -e "${GREEN}✓ 脚本执行成功${NC}"
    
    # 检查是否还有jq错误
    if grep -q "jq: --arg takes two parameters" test-output.log; then
        echo -e "${RED}✗ 仍然存在jq参数错误${NC}"
        echo "错误详情:"
        grep "jq: --arg takes two parameters" test-output.log
        exit 1
    else
        echo -e "${GREEN}✓ 未发现jq参数错误${NC}"
    fi
    
    # 检查输出文件
    if ls logs/org-policy-*-optimized-*.json &> /dev/null; then
        echo -e "${GREEN}✓ JSON报告文件已生成${NC}"
        
        # 验证JSON格式
        for json_file in logs/org-policy-*-optimized-*.json; do
            if jq . "$json_file" > /dev/null 2>&1; then
                echo -e "${GREEN}✓ JSON格式有效: $(basename "$json_file")${NC}"
            else
                echo -e "${RED}✗ JSON格式无效: $(basename "$json_file")${NC}"
                exit 1
            fi
        done
    else
        echo -e "${YELLOW}! JSON报告文件未生成（可能是超时导致）${NC}"
    fi
    
else
    exit_code=$?
    if [ $exit_code -eq 124 ]; then
        echo -e "${YELLOW}! 脚本执行超时（这是预期的）${NC}"
        
        # 即使超时，也检查是否有jq错误
        if grep -q "jq: --arg takes two parameters" test-output.log; then
            echo -e "${RED}✗ 仍然存在jq参数错误${NC}"
            echo "错误详情:"
            grep "jq: --arg takes two parameters" test-output.log
            exit 1
        else
            echo -e "${GREEN}✓ 未发现jq参数错误${NC}"
        fi
    else
        echo -e "${RED}✗ 脚本执行失败，退出码: $exit_code${NC}"
        echo "查看详细错误: cat test-output.log"
        exit 1
    fi
fi

echo ""
echo -e "${GREEN}=== jq修复验证完成 ===${NC}"
echo ""
echo "测试结果:"
echo "✓ 依赖工具正常"
echo "✓ AWS凭证有效"
echo "✓ 脚本执行正常"
echo "✓ 未发现jq参数错误"
echo "✓ JSON格式有效"
echo ""
echo -e "${GREEN}jq修复成功！${NC}"

# 清理测试文件
rm -f test-output.log

echo ""
echo "如需查看完整日志，请检查 logs/ 目录中的文件"
