#!/bin/bash

# 性能测试脚本 - 对比原版本和优化版本的执行时间

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== AWS组织策略检查工具性能测试 ===${NC}"
echo ""

# 检查脚本是否存在
if [ ! -f "check-org-policies.sh" ]; then
    echo -e "${RED}错误: 找不到原版本脚本 check-org-policies.sh${NC}"
    exit 1
fi

if [ ! -f "check-org-policies-optimized.sh" ]; then
    echo -e "${RED}错误: 找不到优化版本脚本 check-org-policies-optimized.sh${NC}"
    exit 1
fi

# 确保脚本有执行权限
chmod +x check-org-policies.sh
chmod +x check-org-policies-optimized.sh

# 测试配置
PARALLEL_JOBS_LIST=(5 10 15 20)
TEST_ROUNDS=1  # 可以增加测试轮数获得更准确的平均值

echo -e "${YELLOW}测试配置:${NC}"
echo "- 测试轮数: $TEST_ROUNDS"
echo "- 并行任务数测试: ${PARALLEL_JOBS_LIST[*]}"
echo ""

# 创建测试结果目录
TEST_RESULTS_DIR="performance-test-results"
mkdir -p "$TEST_RESULTS_DIR"

# 测试结果文件
RESULTS_FILE="$TEST_RESULTS_DIR/performance-test-$(date +%Y%m%d-%H%M%S).txt"

echo "性能测试结果 - $(date)" > "$RESULTS_FILE"
echo "========================================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# 函数：运行单次测试
run_test() {
    local script_name="$1"
    local script_path="$2"
    local parallel_jobs="$3"
    local round="$4"
    
    echo -e "${BLUE}测试 $script_name (并行任务数: $parallel_jobs, 第 $round 轮)...${NC}"
    
    # 设置环境变量
    export MAX_PARALLEL_JOBS="$parallel_jobs"
    
    # 记录开始时间
    start_time=$(date +%s.%N)
    
    # 运行脚本（重定向输出避免干扰）
    if ./"$script_path" > /dev/null 2>&1; then
        # 记录结束时间
        end_time=$(date +%s.%N)
        
        # 计算执行时间
        duration=$(echo "$end_time - $start_time" | bc -l)
        
        echo "  执行时间: ${duration}秒"
        echo "$script_name (并行任务数: $parallel_jobs, 第 $round 轮): ${duration}秒" >> "$RESULTS_FILE"
        
        return 0
    else
        echo -e "${RED}  执行失败${NC}"
        echo "$script_name (并行任务数: $parallel_jobs, 第 $round 轮): 执行失败" >> "$RESULTS_FILE"
        return 1
    fi
}

# 函数：计算平均值
calculate_average() {
    local values=("$@")
    local sum=0
    local count=0
    
    for value in "${values[@]}"; do
        if [[ "$value" =~ ^[0-9]+\.?[0-9]*$ ]]; then
            sum=$(echo "$sum + $value" | bc -l)
            ((count++))
        fi
    done
    
    if [ "$count" -gt 0 ]; then
        echo "scale=3; $sum / $count" | bc -l
    else
        echo "0"
    fi
}

# 存储测试结果
declare -A original_times
declare -A optimized_times

echo -e "${YELLOW}开始性能测试...${NC}"
echo ""

# 测试原版本（仅测试一次，因为不支持并行配置）
echo -e "${GREEN}测试原版本脚本...${NC}"
original_results=()

for round in $(seq 1 $TEST_ROUNDS); do
    if run_test "原版本" "check-org-policies.sh" "N/A" "$round"; then
        # 从日志中提取执行时间（如果脚本记录了时间）
        # 这里我们使用实际测量的时间
        last_duration=$(tail -1 "$RESULTS_FILE" | grep -o '[0-9]*\.[0-9]*秒' | sed 's/秒//')
        if [ -n "$last_duration" ]; then
            original_results+=("$last_duration")
        fi
    fi
done

echo ""

# 测试优化版本
echo -e "${GREEN}测试优化版本脚本...${NC}"

for parallel_jobs in "${PARALLEL_JOBS_LIST[@]}"; do
    echo -e "${YELLOW}测试并行任务数: $parallel_jobs${NC}"
    optimized_results=()
    
    for round in $(seq 1 $TEST_ROUNDS); do
        if run_test "优化版本" "check-org-policies-optimized.sh" "$parallel_jobs" "$round"; then
            last_duration=$(tail -1 "$RESULTS_FILE" | grep -o '[0-9]*\.[0-9]*秒' | sed 's/秒//')
            if [ -n "$last_duration" ]; then
                optimized_results+=("$last_duration")
            fi
        fi
    done
    
    # 计算平均时间
    if [ ${#optimized_results[@]} -gt 0 ]; then
        avg_time=$(calculate_average "${optimized_results[@]}")
        optimized_times["$parallel_jobs"]="$avg_time"
    fi
    
    echo ""
done

# 生成测试报告
echo "" >> "$RESULTS_FILE"
echo "========================================" >> "$RESULTS_FILE"
echo "测试总结:" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# 计算原版本平均时间
if [ ${#original_results[@]} -gt 0 ]; then
    original_avg=$(calculate_average "${original_results[@]}")
    echo "原版本平均执行时间: ${original_avg}秒" >> "$RESULTS_FILE"
else
    original_avg="0"
    echo "原版本: 测试失败" >> "$RESULTS_FILE"
fi

echo "" >> "$RESULTS_FILE"
echo "优化版本测试结果:" >> "$RESULTS_FILE"

for parallel_jobs in "${PARALLEL_JOBS_LIST[@]}"; do
    if [ -n "${optimized_times[$parallel_jobs]}" ]; then
        opt_time="${optimized_times[$parallel_jobs]}"
        echo "- 并行任务数 $parallel_jobs: ${opt_time}秒" >> "$RESULTS_FILE"
        
        # 计算性能提升
        if [ "$original_avg" != "0" ] && [ "$opt_time" != "0" ]; then
            improvement=$(echo "scale=2; $original_avg / $opt_time" | bc -l)
            echo "  性能提升: ${improvement}倍" >> "$RESULTS_FILE"
        fi
    else
        echo "- 并行任务数 $parallel_jobs: 测试失败" >> "$RESULTS_FILE"
    fi
done

# 显示测试结果
echo -e "${GREEN}=== 测试完成 ===${NC}"
echo ""
echo -e "${YELLOW}测试结果摘要:${NC}"

if [ "$original_avg" != "0" ]; then
    echo "原版本平均执行时间: ${original_avg}秒"
else
    echo "原版本: 测试失败"
fi

echo ""
echo "优化版本测试结果:"

best_time="999999"
best_parallel=""

for parallel_jobs in "${PARALLEL_JOBS_LIST[@]}"; do
    if [ -n "${optimized_times[$parallel_jobs]}" ]; then
        opt_time="${optimized_times[$parallel_jobs]}"
        echo "- 并行任务数 $parallel_jobs: ${opt_time}秒"
        
        # 计算性能提升
        if [ "$original_avg" != "0" ] && [ "$opt_time" != "0" ]; then
            improvement=$(echo "scale=2; $original_avg / $opt_time" | bc -l)
            echo "  性能提升: ${improvement}倍"
        fi
        
        # 找出最佳性能配置
        if (( $(echo "$opt_time < $best_time" | bc -l) )); then
            best_time="$opt_time"
            best_parallel="$parallel_jobs"
        fi
    else
        echo "- 并行任务数 $parallel_jobs: 测试失败"
    fi
done

if [ -n "$best_parallel" ]; then
    echo ""
    echo -e "${GREEN}推荐配置: 并行任务数 $best_parallel (执行时间: ${best_time}秒)${NC}"
fi

echo ""
echo "详细测试结果已保存到: $RESULTS_FILE"

# 清理环境变量
unset MAX_PARALLEL_JOBS
