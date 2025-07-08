#!/bin/bash

# 并发测试脚本 - 测试不同并发数的性能

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== 并发性能测试 ===${NC}"
echo ""

# 检查脚本是否存在
if [ ! -f "check-org-policies-optimized-v2.sh" ]; then
    echo -e "${RED}错误: 找不到优化版本 v2 脚本${NC}"
    exit 1
fi

# 检查AWS凭证
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}错误: AWS凭证未配置或无效${NC}"
    exit 1
fi

# 检测环境
if [ -n "${AWS_EXECUTION_ENV}" ] && [[ "${AWS_EXECUTION_ENV}" == *"CloudShell"* ]]; then
    echo -e "${YELLOW}检测到 CloudShell 环境${NC}"
    CONCURRENCY_LEVELS=(3 5 8 10)
    MAX_TEST_TIME=180  # 3分钟超时
else
    echo -e "${YELLOW}检测到本地/服务器环境${NC}"
    CONCURRENCY_LEVELS=(5 10 15 20)
    MAX_TEST_TIME=300  # 5分钟超时
fi

echo "测试并发级别: ${CONCURRENCY_LEVELS[*]}"
echo "最大测试时间: ${MAX_TEST_TIME}秒"
echo ""

# 创建测试结果目录
TEST_RESULTS_DIR="concurrency-test-results"
mkdir -p "$TEST_RESULTS_DIR"

# 测试结果文件
RESULTS_FILE="$TEST_RESULTS_DIR/concurrency-test-$(date +%Y%m%d-%H%M%S).txt"

echo "并发性能测试结果 - $(date)" > "$RESULTS_FILE"
echo "环境: ${AWS_EXECUTION_ENV:-本地环境}" >> "$RESULTS_FILE"
echo "========================================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# 获取系统信息
echo "系统信息:" >> "$RESULTS_FILE"
echo "- CPU核心数: $(nproc 2>/dev/null || echo "未知")" >> "$RESULTS_FILE"
echo "- 内存总量: $(free -h 2>/dev/null | grep Mem | awk '{print $2}' || echo "未知")" >> "$RESULTS_FILE"
echo "- 进程限制: $(ulimit -u 2>/dev/null || echo "未知")" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# 测试函数
run_concurrency_test() {
    local concurrency="$1"
    local test_num="$2"
    
    echo -e "${BLUE}测试 $test_num: 并发数 $concurrency${NC}"
    
    # 记录开始时间
    local start_time=$(date +%s.%N)
    
    # 运行脚本
    local exit_code=0
    if timeout $MAX_TEST_TIME bash -c "MAX_PARALLEL_JOBS=$concurrency ./check-org-policies-optimized-v2.sh" > "$TEST_RESULTS_DIR/test-$concurrency.log" 2>&1; then
        # 记录结束时间
        local end_time=$(date +%s.%N)
        local duration=$(echo "$end_time - $start_time" | bc -l)
        
        echo -e "${GREEN}✓ 完成，耗时: ${duration}秒${NC}"
        echo "并发数 $concurrency: ${duration}秒 (成功)" >> "$RESULTS_FILE"
        
        # 检查是否有错误
        local error_count=$(grep -c "错误\|失败\|ERROR\|FAILED" "$TEST_RESULTS_DIR/test-$concurrency.log" 2>/dev/null || echo "0")
        if [ "$error_count" -gt 0 ]; then
            echo "  警告: 发现 $error_count 个错误" >> "$RESULTS_FILE"
            echo -e "${YELLOW}  警告: 发现 $error_count 个错误${NC}"
        fi
        
        return 0
    else
        exit_code=$?
        local end_time=$(date +%s.%N)
        local duration=$(echo "$end_time - $start_time" | bc -l)
        
        if [ $exit_code -eq 124 ]; then
            echo -e "${RED}✗ 超时 (${MAX_TEST_TIME}秒)${NC}"
            echo "并发数 $concurrency: 超时 (${MAX_TEST_TIME}秒)" >> "$RESULTS_FILE"
        else
            echo -e "${RED}✗ 失败，退出码: $exit_code，耗时: ${duration}秒${NC}"
            echo "并发数 $concurrency: 失败 (退出码: $exit_code, 耗时: ${duration}秒)" >> "$RESULTS_FILE"
        fi
        
        return 1
    fi
}

# 运行测试
echo -e "${YELLOW}开始并发性能测试...${NC}"
echo ""

successful_tests=0
total_tests=${#CONCURRENCY_LEVELS[@]}

for i in "${!CONCURRENCY_LEVELS[@]}"; do
    concurrency=${CONCURRENCY_LEVELS[$i]}
    test_num=$((i + 1))
    
    if run_concurrency_test "$concurrency" "$test_num"; then
        ((successful_tests++))
    fi
    
    echo ""
    
    # 如果不是最后一个测试，等待一下让系统恢复
    if [ $test_num -lt $total_tests ]; then
        echo "等待系统恢复..."
        sleep 10
    fi
done

# 生成测试报告
echo "" >> "$RESULTS_FILE"
echo "========================================" >> "$RESULTS_FILE"
echo "测试总结:" >> "$RESULTS_FILE"
echo "- 总测试数: $total_tests" >> "$RESULTS_FILE"
echo "- 成功测试数: $successful_tests" >> "$RESULTS_FILE"
echo "- 失败测试数: $((total_tests - successful_tests))" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# 分析最佳配置
echo "性能分析:" >> "$RESULTS_FILE"
best_concurrency=""
best_time="999999"

for concurrency in "${CONCURRENCY_LEVELS[@]}"; do
    if [ -f "$TEST_RESULTS_DIR/test-$concurrency.log" ]; then
        # 尝试从日志中提取执行时间
        if grep -q "检查耗时:" "$TEST_RESULTS_DIR/test-$concurrency.log"; then
            time_info=$(grep "检查耗时:" "$TEST_RESULTS_DIR/test-$concurrency.log" | head -1)
            echo "- 并发数 $concurrency: $time_info" >> "$RESULTS_FILE"
        fi
    fi
done

# 显示测试结果
echo -e "${GREEN}=== 测试完成 ===${NC}"
echo ""
echo -e "${YELLOW}测试结果摘要:${NC}"
echo "总测试数: $total_tests"
echo "成功测试数: $successful_tests"
echo "失败测试数: $((total_tests - successful_tests))"
echo ""

if [ $successful_tests -gt 0 ]; then
    echo -e "${GREEN}至少有 $successful_tests 个并发配置可以正常工作${NC}"
    
    # 推荐配置
    if [ -n "${AWS_EXECUTION_ENV}" ] && [[ "${AWS_EXECUTION_ENV}" == *"CloudShell"* ]]; then
        echo ""
        echo -e "${BLUE}CloudShell 环境推荐配置:${NC}"
        echo "- 保守配置: MAX_PARALLEL_JOBS=5"
        echo "- 平衡配置: MAX_PARALLEL_JOBS=8"
        echo "- 如果系统资源充足: MAX_PARALLEL_JOBS=10"
    else
        echo ""
        echo -e "${BLUE}本地/服务器环境推荐配置:${NC}"
        echo "- 平衡配置: MAX_PARALLEL_JOBS=10"
        echo "- 高性能配置: MAX_PARALLEL_JOBS=15"
        echo "- 如果系统资源充足: MAX_PARALLEL_JOBS=20"
    fi
else
    echo -e "${RED}所有测试都失败了，建议检查环境配置${NC}"
fi

echo ""
echo "详细测试结果已保存到: $RESULTS_FILE"
echo ""
echo "查看各个测试的详细日志:"
for concurrency in "${CONCURRENCY_LEVELS[@]}"; do
    if [ -f "$TEST_RESULTS_DIR/test-$concurrency.log" ]; then
        echo "- 并发数 $concurrency: $TEST_RESULTS_DIR/test-$concurrency.log"
    fi
done

echo ""
echo -e "${BLUE}使用推荐配置运行脚本:${NC}"
if [ -n "${AWS_EXECUTION_ENV}" ] && [[ "${AWS_EXECUTION_ENV}" == *"CloudShell"* ]]; then
    echo "MAX_PARALLEL_JOBS=8 ./check-org-policies-optimized-v2.sh"
else
    echo "MAX_PARALLEL_JOBS=15 ./check-org-policies-optimized-v2.sh"
fi
