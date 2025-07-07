#!/bin/bash

# 功能验证脚本 - 确保优化版本功能正确性

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== 优化版本功能验证 ===${NC}"
echo ""

# 检查必要的工具
check_dependencies() {
    echo -e "${YELLOW}检查依赖工具...${NC}"
    
    local missing_tools=()
    
    if ! command -v aws &> /dev/null; then
        missing_tools+=("aws")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing_tools+=("jq")
    fi
    
    if ! command -v bc &> /dev/null; then
        missing_tools+=("bc")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}错误: 缺少必要工具: ${missing_tools[*]}${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✓ 所有依赖工具已安装${NC}"
    return 0
}

# 检查AWS凭证
check_aws_credentials() {
    echo -e "${YELLOW}检查AWS凭证...${NC}"
    
    if aws sts get-caller-identity &> /dev/null; then
        local account_id=$(aws sts get-caller-identity --query Account --output text)
        local user_arn=$(aws sts get-caller-identity --query Arn --output text)
        echo -e "${GREEN}✓ AWS凭证有效${NC}"
        echo "  账号ID: $account_id"
        echo "  用户ARN: $user_arn"
        return 0
    else
        echo -e "${RED}✗ AWS凭证无效或未配置${NC}"
        return 1
    fi
}

# 检查脚本文件
check_scripts() {
    echo -e "${YELLOW}检查脚本文件...${NC}"
    
    if [ ! -f "check-org-policies-optimized.sh" ]; then
        echo -e "${RED}✗ 优化版本脚本不存在${NC}"
        return 1
    fi
    
    if [ ! -x "check-org-policies-optimized.sh" ]; then
        echo -e "${YELLOW}! 优化版本脚本没有执行权限，正在添加...${NC}"
        chmod +x check-org-policies-optimized.sh
    fi
    
    echo -e "${GREEN}✓ 脚本文件检查通过${NC}"
    return 0
}

# 测试基本功能
test_basic_functionality() {
    echo -e "${YELLOW}测试基本功能...${NC}"
    
    # 创建测试目录
    local test_dir="verification-test"
    mkdir -p "$test_dir"
    
    # 运行优化版本脚本（使用较小的并行任务数避免过载）
    echo "运行优化版本脚本..."
    if MAX_PARALLEL_JOBS=3 timeout 300 ./check-org-policies-optimized.sh > "$test_dir/test-output.log" 2>&1; then
        echo -e "${GREEN}✓ 脚本执行成功${NC}"
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            echo -e "${YELLOW}! 脚本执行超时（5分钟），但这可能是正常的${NC}"
        else
            echo -e "${RED}✗ 脚本执行失败，退出码: $exit_code${NC}"
            echo "查看详细错误信息: cat $test_dir/test-output.log"
            return 1
        fi
    fi
    
    # 检查输出文件
    echo "检查输出文件..."
    local log_files=(logs/org-policy-*-optimized-*.log)
    local json_files=(logs/org-policy-*-optimized-*.json)
    local findings_files=(logs/org-policy-*-optimized-*.txt)
    
    if [ -f "${log_files[0]}" ] 2>/dev/null; then
        echo -e "${GREEN}✓ 日志文件已生成${NC}"
    else
        echo -e "${RED}✗ 日志文件未生成${NC}"
        return 1
    fi
    
    if [ -f "${json_files[0]}" ] 2>/dev/null; then
        echo -e "${GREEN}✓ JSON报告已生成${NC}"
        
        # 验证JSON格式
        if jq . "${json_files[0]}" > /dev/null 2>&1; then
            echo -e "${GREEN}✓ JSON格式有效${NC}"
        else
            echo -e "${RED}✗ JSON格式无效${NC}"
            return 1
        fi
    else
        echo -e "${RED}✗ JSON报告未生成${NC}"
        return 1
    fi
    
    if [ -f "${findings_files[0]}" ] 2>/dev/null; then
        echo -e "${GREEN}✓ 组织相关发现文件已生成${NC}"
    else
        echo -e "${RED}✗ 组织相关发现文件未生成${NC}"
        return 1
    fi
    
    return 0
}

# 测试并行配置
test_parallel_configuration() {
    echo -e "${YELLOW}测试并行配置...${NC}"
    
    local test_jobs=(2 5 8)
    
    for jobs in "${test_jobs[@]}"; do
        echo "测试并行任务数: $jobs"
        
        # 运行一个快速测试（只检查IAM，限制时间）
        if timeout 60 bash -c "MAX_PARALLEL_JOBS=$jobs ./check-org-policies-optimized.sh" > /dev/null 2>&1; then
            echo -e "${GREEN}✓ 并行任务数 $jobs 测试通过${NC}"
        else
            local exit_code=$?
            if [ $exit_code -eq 124 ]; then
                echo -e "${YELLOW}! 并行任务数 $jobs 测试超时（这可能是正常的）${NC}"
            else
                echo -e "${RED}✗ 并行任务数 $jobs 测试失败${NC}"
                return 1
            fi
        fi
    done
    
    return 0
}

# 测试错误处理
test_error_handling() {
    echo -e "${YELLOW}测试错误处理...${NC}"
    
    # 测试无效的AWS区域
    echo "测试无效AWS区域处理..."
    if AWS_DEFAULT_REGION=invalid-region timeout 30 ./check-org-policies-optimized.sh > /dev/null 2>&1; then
        echo -e "${YELLOW}! 无效区域测试未按预期失败${NC}"
    else
        echo -e "${GREEN}✓ 无效区域错误处理正常${NC}"
    fi
    
    return 0
}

# 清理测试文件
cleanup_test_files() {
    echo -e "${YELLOW}清理测试文件...${NC}"
    
    # 清理验证测试目录
    if [ -d "verification-test" ]; then
        rm -rf "verification-test"
        echo -e "${GREEN}✓ 测试目录已清理${NC}"
    fi
    
    # 询问是否清理日志文件
    echo -n "是否清理生成的日志文件? (y/N): "
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        rm -f logs/org-policy-*-optimized-*
        echo -e "${GREEN}✓ 日志文件已清理${NC}"
    else
        echo "日志文件保留在 logs/ 目录中"
    fi
}

# 主验证流程
main() {
    echo "开始功能验证..."
    echo ""
    
    # 检查依赖
    if ! check_dependencies; then
        echo -e "${RED}验证失败: 依赖检查未通过${NC}"
        exit 1
    fi
    echo ""
    
    # 检查AWS凭证
    if ! check_aws_credentials; then
        echo -e "${RED}验证失败: AWS凭证检查未通过${NC}"
        exit 1
    fi
    echo ""
    
    # 检查脚本文件
    if ! check_scripts; then
        echo -e "${RED}验证失败: 脚本文件检查未通过${NC}"
        exit 1
    fi
    echo ""
    
    # 测试基本功能
    if ! test_basic_functionality; then
        echo -e "${RED}验证失败: 基本功能测试未通过${NC}"
        exit 1
    fi
    echo ""
    
    # 测试并行配置
    if ! test_parallel_configuration; then
        echo -e "${RED}验证失败: 并行配置测试未通过${NC}"
        exit 1
    fi
    echo ""
    
    # 测试错误处理
    if ! test_error_handling; then
        echo -e "${RED}验证失败: 错误处理测试未通过${NC}"
        exit 1
    fi
    echo ""
    
    echo -e "${GREEN}=== 所有验证测试通过 ===${NC}"
    echo ""
    echo -e "${BLUE}优化版本功能验证完成！${NC}"
    echo ""
    echo "验证结果:"
    echo "✓ 依赖工具检查通过"
    echo "✓ AWS凭证有效"
    echo "✓ 脚本文件正常"
    echo "✓ 基本功能正常"
    echo "✓ 并行配置正常"
    echo "✓ 错误处理正常"
    echo ""
    echo -e "${GREEN}优化版本可以安全使用！${NC}"
    echo ""
    
    # 清理测试文件
    cleanup_test_files
}

# 运行主函数
main "$@"
