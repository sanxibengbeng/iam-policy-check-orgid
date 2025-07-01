#!/bin/bash

# AWS账号组织策略检查脚本 - CloudShell优化版本
# 用于检查账号中所有服务的策略是否包含组织相关配置

# 改进错误处理
set -o pipefail

# 调试模式
if [ "${DEBUG:-}" = "1" ]; then
    set -x
fi

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 创建logs目录
LOGS_DIR="logs"
mkdir -p "$LOGS_DIR"

# 日志文件
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_FILE="$LOGS_DIR/org-policy-check-$TIMESTAMP.log"
DETAILED_LOG_FILE="$LOGS_DIR/org-policy-detailed-$TIMESTAMP.log"
ISSUES_FILE="$LOGS_DIR/org-policy-issues-$TIMESTAMP.json"

echo -e "${BLUE}=== AWS账号组织策略检查工具 (CloudShell优化版) ===${NC}"
echo "主日志文件: $LOG_FILE"
echo "详细日志文件: $DETAILED_LOG_FILE"
echo "问题报告: $ISSUES_FILE"
echo ""

# 初始化问题报告文件
echo '{"issues": [], "summary": {"total_checks": 0, "issues_found": 0}, "check_details": []}' > "$ISSUES_FILE"

# 初始化日志文件
echo "AWS账号组织策略检查 - $(date)" > "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

echo "AWS账号组织策略检查详细日志 - $(date)" > "$DETAILED_LOG_FILE"
echo "========================================" >> "$DETAILED_LOG_FILE"

# 错误处理函数
handle_error() {
    local service="$1"
    local operation="$2"
    local error_msg="$3"
    
    echo -e "${YELLOW}[警告] $service - $operation: $error_msg${NC}"
    echo "WARNING: $service - $operation: $error_msg" >> "$LOG_FILE"
}

# 记录问题的函数
log_issue() {
    local service="$1"
    local resource="$2"
    local issue="$3"
    local details="$4"
    
    echo -e "${RED}[问题] $service - $resource: $issue${NC}"
    echo "$service - $resource: $issue - $details" >> "$LOG_FILE"
    
    # 添加到JSON报告
    if command -v jq > /dev/null 2>&1; then
        jq --arg service "$service" --arg resource "$resource" --arg issue "$issue" --arg details "$details" \
           '.issues += [{"service": $service, "resource": $resource, "issue": $issue, "details": $details}] | .summary.issues_found += 1' \
           "$ISSUES_FILE" > tmp.json && mv tmp.json "$ISSUES_FILE"
    fi
}

# 记录详细检查信息
log_check_detail() {
    local service="$1"
    local resource="$2"
    local status="$3"
    local message="$4"
    
    echo "[$service] $resource: $status - $message" >> "$DETAILED_LOG_FILE"
    
    # 添加到JSON报告的详细记录
    if command -v jq > /dev/null 2>&1; then
        jq --arg service "$service" --arg resource "$resource" --arg status "$status" --arg message "$message" \
           '.check_details += [{"service": $service, "resource": $resource, "status": $status, "message": $message, "timestamp": now | strftime("%Y-%m-%d %H:%M:%S")}]' \
           "$ISSUES_FILE" > tmp.json && mv tmp.json "$ISSUES_FILE"
    fi
}

# 更新检查计数
update_check_count() {
    if command -v jq > /dev/null 2>&1; then
        jq '.summary.total_checks += 1' "$ISSUES_FILE" > tmp.json && mv tmp.json "$ISSUES_FILE"
    fi
}

# 检查字符串中是否包含组织相关关键词
check_org_keywords() {
    local content="$1"
    local keywords=(
        "aws:PrincipalOrgID"
        "aws:PrincipalOrgPaths"
        "aws:ResourceOrgID"
        "aws:ResourceOrgPaths"
        "aws:SourceOrgID"
        "aws:SourceOrgPaths"
        "organizations:"
        "o-[a-z0-9]{10}"
        "ou-[a-z0-9]+-[a-z0-9]{8}"
    )
    
    for keyword in "${keywords[@]}"; do
        if echo "$content" | grep -qi "$keyword"; then
            return 0
        fi
    done
    return 1
}

# ========================================
# 检查函数定义
# ========================================

# 1. 检查IAM策略 - 简化版本
check_iam_policies() {
    echo -e "${BLUE}1. 检查IAM策略${NC}"
    update_check_count
    
    local checked_roles=0
    local checked_users=0
    
    # 检查IAM角色 - 使用更安全的方法
    echo "检查IAM角色..."
    
    # 创建临时文件存储角色列表
    local roles_temp=$(mktemp)
    
    if aws iam list-roles --query 'Roles[].RoleName' --output text > "$roles_temp" 2>/dev/null; then
        # 逐行处理角色
        while IFS=$'\t' read -ra ROLES; do
            for role in "${ROLES[@]}"; do
                if [ -n "$role" ] && [ "$role" != "None" ]; then
                    ((checked_roles++))
                    echo "  检查角色: $role"
                    log_check_detail "IAM" "Role:$role" "检查中" "检查角色信任策略"
                    
                    # 获取角色信任策略
                    local policy_doc
                    if policy_doc=$(aws iam get-role --role-name "$role" --query 'Role.AssumeRolePolicyDocument' --output text 2>/dev/null); then
                        if [ -n "$policy_doc" ] && [ "$policy_doc" != "None" ]; then
                            if check_org_keywords "$policy_doc"; then
                                log_issue "IAM" "Role:$role" "信任策略包含组织相关配置" "$policy_doc"
                                log_check_detail "IAM" "Role:$role" "有问题" "信任策略包含组织相关配置"
                            else
                                log_check_detail "IAM" "Role:$role" "正常" "信任策略无组织相关配置"
                            fi
                        else
                            log_check_detail "IAM" "Role:$role" "无策略" "未找到信任策略"
                        fi
                    else
                        handle_error "IAM" "Role:$role" "无法获取角色信任策略"
                    fi
                    
                    # 限制检查数量避免超时
                    if [ $checked_roles -ge 50 ]; then
                        echo "  已检查50个角色，跳过剩余角色避免超时"
                        break 2
                    fi
                fi
            done
        done < "$roles_temp"
    else
        handle_error "IAM" "list-roles" "无法获取IAM角色列表"
    fi
    
    rm -f "$roles_temp"
    
    # 检查IAM用户 - 简化版本
    echo "检查IAM用户..."
    
    local users_temp=$(mktemp)
    
    if aws iam list-users --query 'Users[0:20].UserName' --output text > "$users_temp" 2>/dev/null; then
        while IFS=$'\t' read -ra USERS; do
            for user in "${USERS[@]}"; do
                if [ -n "$user" ] && [ "$user" != "None" ]; then
                    ((checked_users++))
                    echo "  检查用户: $user"
                    log_check_detail "IAM" "User:$user" "检查中" "检查用户"
                fi
            done
        done < "$users_temp"
    else
        handle_error "IAM" "list-users" "无法获取IAM用户列表"
    fi
    
    rm -f "$users_temp"
    
    echo "IAM检查完成: 角色($checked_roles), 用户($checked_users)"
    echo "IAM检查完成: 角色($checked_roles), 用户($checked_users)" >> "$LOG_FILE"
}

# 2. 检查S3存储桶策略 - 简化版本
check_s3_policies() {
    echo -e "${BLUE}2. 检查S3存储桶策略${NC}"
    update_check_count
    
    local checked_buckets=0
    
    echo "检查S3存储桶..."
    
    local buckets_temp=$(mktemp)
    
    if aws s3api list-buckets --query 'Buckets[0:20].Name' --output text > "$buckets_temp" 2>/dev/null; then
        while IFS=$'\t' read -ra BUCKETS; do
            for bucket in "${BUCKETS[@]}"; do
                if [ -n "$bucket" ] && [ "$bucket" != "None" ]; then
                    ((checked_buckets++))
                    echo "  检查存储桶: $bucket"
                    log_check_detail "S3" "Bucket:$bucket" "检查中" "检查存储桶策略"
                    
                    local bucket_policy
                    if bucket_policy=$(aws s3api get-bucket-policy --bucket "$bucket" --query 'Policy' --output text 2>/dev/null); then
                        if [ -n "$bucket_policy" ] && [ "$bucket_policy" != "None" ]; then
                            if check_org_keywords "$bucket_policy"; then
                                log_issue "S3" "Bucket:$bucket" "存储桶策略包含组织相关配置" "$bucket_policy"
                                log_check_detail "S3" "Bucket:$bucket" "有问题" "存储桶策略包含组织相关配置"
                            else
                                log_check_detail "S3" "Bucket:$bucket" "正常" "存储桶策略无组织相关配置"
                            fi
                        else
                            log_check_detail "S3" "Bucket:$bucket" "无策略" "存储桶无策略配置"
                        fi
                    else
                        log_check_detail "S3" "Bucket:$bucket" "无策略" "存储桶无策略或无权限访问"
                    fi
                fi
            done
        done < "$buckets_temp"
    else
        handle_error "S3" "list-buckets" "无法获取S3存储桶列表"
    fi
    
    rm -f "$buckets_temp"
    
    echo "S3检查完成: 存储桶($checked_buckets)"
    echo "S3检查完成: 存储桶($checked_buckets)" >> "$LOG_FILE"
}

# ========================================
# 主执行流程
# ========================================

echo -e "${YELLOW}开始检查各服务策略...${NC}"
echo "开始检查各服务策略 - $(date)" >> "$LOG_FILE"

# 检查AWS CLI是否可用
if ! aws sts get-caller-identity > /dev/null 2>&1; then
    echo -e "${RED}错误: AWS CLI无法工作，请检查凭证配置${NC}"
    exit 1
fi

echo -e "${GREEN}AWS CLI工作正常${NC}"

# 执行检查函数 - 先只执行前两个进行测试
check_iam_policies
check_s3_policies

echo ""
echo -e "${GREEN}=== 检查完成 ===${NC}"
echo "检查完成 - $(date)" >> "$LOG_FILE"

# 显示总结
if command -v jq > /dev/null 2>&1; then
    total_checks=$(jq -r '.summary.total_checks' "$ISSUES_FILE")
    issues_found=$(jq -r '.summary.issues_found' "$ISSUES_FILE")
else
    total_checks="N/A"
    issues_found="N/A"
fi

echo "总检查项目: $total_checks"
echo "发现问题: $issues_found"

echo ""
echo "检查完成时间: $(date)"
echo "日志文件位置:"
echo "- 主日志: $LOG_FILE"
echo "- 详细日志: $DETAILED_LOG_FILE"
echo "- JSON报告: $ISSUES_FILE"
