#!/bin/bash

# AWS账号组织策略检查脚本 - 优化版本 v2
# 修复并发实现问题

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
NC='\033[0m'

# 并发配置 - 针对CloudShell优化
if [ -n "${AWS_EXECUTION_ENV}" ] && [[ "${AWS_EXECUTION_ENV}" == *"CloudShell"* ]]; then
    # CloudShell环境默认配置
    MAX_PARALLEL_JOBS=${MAX_PARALLEL_JOBS:-8}
    echo "检测到CloudShell环境，使用优化配置"
else
    # 其他环境配置
    MAX_PARALLEL_JOBS=${MAX_PARALLEL_JOBS:-15}
fi

TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# 创建logs目录
LOGS_DIR="logs"
mkdir -p "$LOGS_DIR"

# 日志文件
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_FILE="$LOGS_DIR/org-policy-check-optimized-v2-$TIMESTAMP.log"
DETAILED_LOG_FILE="$LOGS_DIR/org-policy-detailed-optimized-v2-$TIMESTAMP.log"
ISSUES_FILE="$LOGS_DIR/org-policy-issues-optimized-v2-$TIMESTAMP.json"
ORG_FINDINGS_FILE="$LOGS_DIR/org-policy-findings-optimized-v2-$TIMESTAMP.txt"

echo -e "${BLUE}=== AWS账号组织策略检查工具 (优化版本 v2) ===${NC}"
echo "最大并行任务数: $MAX_PARALLEL_JOBS"
echo "主日志文件: $LOG_FILE"
echo "详细日志文件: $DETAILED_LOG_FILE"
echo "问题报告: $ISSUES_FILE"
echo "组织相关发现: $ORG_FINDINGS_FILE"
echo ""

# 初始化文件
echo '{"issues": [], "summary": {"total_checks": 0, "issues_found": 0}, "check_details": []}' > "$ISSUES_FILE"

echo "AWS账号组织策略检查 - 组织相关发现 (优化版本 v2)" > "$ORG_FINDINGS_FILE"
echo "检查时间: $(date)" >> "$ORG_FINDINGS_FILE"
echo "========================================" >> "$ORG_FINDINGS_FILE"
echo "" >> "$ORG_FINDINGS_FILE"

echo "AWS账号组织策略检查 (优化版本 v2) - $(date)" > "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"
echo ""

echo "AWS账号组织策略检查详细日志 (优化版本 v2) - $(date)" > "$DETAILED_LOG_FILE"
echo "========================================" >> "$DETAILED_LOG_FILE"
echo ""

# 线程安全的日志记录函数
safe_log() {
    local message="$1"
    local file="$2"
    
    (
        flock -x 200
        echo "$message" >> "$file"
    ) 200>>"$file.lock"
}

# 线程安全的JSON更新函数
safe_json_update() {
    local jq_args=("$@")
    
    (
        flock -x 200
        jq "${jq_args[@]}" "$ISSUES_FILE" > "$TEMP_DIR/tmp.json" && mv "$TEMP_DIR/tmp.json" "$ISSUES_FILE"
    ) 200>>"$ISSUES_FILE.lock"
}

# 记录问题的函数
log_issue() {
    local service="$1"
    local resource="$2"
    local issue="$3"
    local details="$4"
    
    echo -e "${RED}[问题] $service - $resource: $issue${NC}"
    safe_log "$service - $resource: $issue - $details" "$LOG_FILE"
    
    local safe_service="${service:-unknown}"
    local safe_resource="${resource:-unknown}"
    local safe_issue="${issue:-unknown}"
    local safe_details="${details:-}"
    
    safe_json_update --arg service "$safe_service" --arg resource "$safe_resource" --arg issue "$safe_issue" --arg details "$safe_details" \
       '.issues += [{"service": $service, "resource": $resource, "issue": $issue, "details": $details}] | .summary.issues_found += 1'
}

# 记录详细检查信息
log_check_detail() {
    local service="$1"
    local resource="$2"
    local status="$3"
    local message="$4"
    
    safe_log "[$service] $resource: $status - $message" "$DETAILED_LOG_FILE"
    
    local safe_service="${service:-unknown}"
    local safe_resource="${resource:-unknown}"
    local safe_status="${status:-unknown}"
    local safe_message="${message:-}"
    
    safe_json_update --arg service "$safe_service" --arg resource "$safe_resource" --arg status "$safe_status" --arg message "$safe_message" \
       '.check_details += [{"service": $service, "resource": $resource, "status": $status, "message": $message, "timestamp": now | strftime("%Y-%m-%d %H:%M:%S")}]'
}

# 更新检查计数
update_check_count() {
    safe_json_update '.summary.total_checks += 1'
}

# 线程安全的组织相关发现记录
log_org_finding() {
    local finding_type="$1"
    local resource_name="$2"
    local policy_content="$3"
    
    (
        flock -x 200
        echo "$finding_type: $resource_name" >> "$ORG_FINDINGS_FILE"
        echo "Policy Content: $policy_content" >> "$ORG_FINDINGS_FILE"
        echo "---" >> "$ORG_FINDINGS_FILE"
    ) 200>>"$ORG_FINDINGS_FILE.lock"
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

# 改进的并发控制函数
wait_for_available_slot() {
    local max_jobs="$1"
    
    while true; do
        local current_jobs=$(jobs -r | wc -l)
        if [ "$current_jobs" -lt "$max_jobs" ]; then
            break
        fi
        sleep 0.1
    done
}

# 批量并行处理函数
process_items_in_parallel() {
    local process_func="$1"
    local items_array=("${@:2}")
    local processed_count=0
    
    for item in "${items_array[@]}"; do
        if [ -n "$item" ] && [ "$item" != "None" ]; then
            wait_for_available_slot "$MAX_PARALLEL_JOBS"
            $process_func "$item" &
            ((processed_count++))
            
            # 每处理一定数量的项目显示进度
            if (( processed_count % 10 == 0 )); then
                echo "已启动 $processed_count 个并行任务..."
            fi
        fi
    done
    
    # 等待所有任务完成
    wait
    echo "完成 $processed_count 个项目的处理"
}

# IAM角色处理函数
process_iam_role() {
    local role="$1"
    
    if [ -z "$role" ] || [ "$role" = "None" ]; then
        return 0
    fi
    
    log_check_detail "IAM" "Role:$role" "检查中" "检查角色信任策略"
    
    # 获取角色信任策略
    local policy_doc
    if policy_doc=$(aws iam get-role --role-name "$role" --query 'Role.AssumeRolePolicyDocument' --output text 2>/dev/null); then
        if [ -n "$policy_doc" ] && [ "$policy_doc" != "None" ]; then
            if check_org_keywords "$policy_doc"; then
                log_issue "IAM" "Role:$role" "信任策略包含组织相关配置" "$policy_doc"
                log_check_detail "IAM" "Role:$role" "有问题" "信任策略包含组织相关配置"
                log_org_finding "Role Trust Policy" "$role" "$policy_doc"
            else
                log_check_detail "IAM" "Role:$role" "正常" "信任策略无组织相关配置"
            fi
        else
            log_check_detail "IAM" "Role:$role" "无策略" "未找到信任策略"
        fi
    else
        log_check_detail "IAM" "Role:$role" "错误" "获取角色信任策略失败"
    fi
    
    # 检查附加的客户管理策略
    local policies_output
    if policies_output=$(aws iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null); then
        echo "$policies_output" | tr '\t' '\n' | while read -r policy_arn; do
            if [ -n "$policy_arn" ] && [ "$policy_arn" != "None" ] && [[ "$policy_arn" != *"arn:aws:iam::aws:policy"* ]]; then
                local version_id
                if version_id=$(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text 2>/dev/null); then
                    if [ -n "$version_id" ] && [ "$version_id" != "None" ]; then
                        local policy_content
                        if policy_content=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query 'PolicyVersion.Document' --output text 2>/dev/null); then
                            if [ -n "$policy_content" ] && [ "$policy_content" != "None" ]; then
                                if check_org_keywords "$policy_content"; then
                                    log_issue "IAM" "Policy:$policy_arn" "客户管理策略包含组织相关配置" "$policy_content"
                                    log_check_detail "IAM" "Policy:$policy_arn" "有问题" "客户管理策略包含组织相关配置"
                                    log_org_finding "Customer Managed Policy" "$policy_arn (attached to role: $role)" "$policy_content"
                                else
                                    log_check_detail "IAM" "Policy:$policy_arn" "正常" "客户管理策略无组织相关配置"
                                fi
                            fi
                        fi
                    fi
                fi
            fi
        done
    fi
}

# IAM用户处理函数
process_iam_user() {
    local user="$1"
    
    if [ -z "$user" ] || [ "$user" = "None" ]; then
        return 0
    fi
    
    log_check_detail "IAM" "User:$user" "检查中" "检查用户附加的客户管理策略"
    
    local policies_output
    if policies_output=$(aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null); then
        echo "$policies_output" | tr '\t' '\n' | while read -r policy_arn; do
            if [ -n "$policy_arn" ] && [ "$policy_arn" != "None" ] && [[ "$policy_arn" != *"arn:aws:iam::aws:policy"* ]]; then
                local version_id
                if version_id=$(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text 2>/dev/null); then
                    if [ -n "$version_id" ] && [ "$version_id" != "None" ]; then
                        local policy_content
                        if policy_content=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query 'PolicyVersion.Document' --output text 2>/dev/null); then
                            if [ -n "$policy_content" ] && [ "$policy_content" != "None" ]; then
                                if check_org_keywords "$policy_content"; then
                                    log_issue "IAM" "UserPolicy:$user->$policy_arn" "用户的客户管理策略包含组织相关配置" "$policy_content"
                                    log_check_detail "IAM" "UserPolicy:$user->$policy_arn" "有问题" "用户的客户管理策略包含组织相关配置"
                                    log_org_finding "Customer Managed Policy" "$policy_arn (attached to user: $user)" "$policy_content"
                                else
                                    log_check_detail "IAM" "UserPolicy:$user->$policy_arn" "正常" "用户的客户管理策略无组织相关配置"
                                fi
                            fi
                        fi
                    fi
                fi
            fi
        done
    fi
}

# 独立策略处理函数
process_standalone_policy() {
    local policy_arn="$1"
    
    if [ -z "$policy_arn" ] || [ "$policy_arn" = "None" ]; then
        return 0
    fi
    
    log_check_detail "IAM" "StandalonePolicy:$policy_arn" "检查中" "检查独立的客户管理策略"
    
    local version_id
    if version_id=$(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text 2>/dev/null); then
        if [ -n "$version_id" ] && [ "$version_id" != "None" ]; then
            local policy_content
            if policy_content=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query 'PolicyVersion.Document' --output text 2>/dev/null); then
                if [ -n "$policy_content" ] && [ "$policy_content" != "None" ]; then
                    if check_org_keywords "$policy_content"; then
                        log_issue "IAM" "StandalonePolicy:$policy_arn" "独立的客户管理策略包含组织相关配置" "$policy_content"
                        log_check_detail "IAM" "StandalonePolicy:$policy_arn" "有问题" "独立的客户管理策略包含组织相关配置"
                        log_org_finding "Standalone Customer Managed Policy" "$policy_arn" "$policy_content"
                    else
                        log_check_detail "IAM" "StandalonePolicy:$policy_arn" "正常" "独立的客户管理策略无组织相关配置"
                    fi
                fi
            fi
        fi
    fi
}

# 优化的IAM策略检查
check_iam_policies_optimized() {
    echo -e "${BLUE}1. 检查IAM策略 (仅客户管理策略) - 并行化处理 v2${NC}"
    update_check_count
    
    echo "开始并行检查IAM角色..."
    local roles_list
    if roles_list=$(aws iam list-roles --query 'Roles[].RoleName' --output text 2>/dev/null); then
        local roles_array
        IFS=$'\t' read -ra roles_array <<< "$roles_list"
        echo "发现 ${#roles_array[@]} 个IAM角色"
        process_items_in_parallel "process_iam_role" "${roles_array[@]}"
    else
        echo "获取IAM角色列表失败"
    fi
    
    echo "开始并行检查IAM用户..."
    local users_list
    if users_list=$(aws iam list-users --query 'Users[].UserName' --output text 2>/dev/null); then
        local users_array
        IFS=$'\t' read -ra users_array <<< "$users_list"
        echo "发现 ${#users_array[@]} 个IAM用户"
        process_items_in_parallel "process_iam_user" "${users_array[@]}"
    else
        echo "获取IAM用户列表失败"
    fi
    
    echo "开始并行检查独立的客户管理策略..."
    local policies_list
    if policies_list=$(aws iam list-policies --scope Local --query 'Policies[].Arn' --output text 2>/dev/null); then
        local policies_array
        IFS=$'\t' read -ra policies_array <<< "$policies_list"
        echo "发现 ${#policies_array[@]} 个客户管理策略"
        process_items_in_parallel "process_standalone_policy" "${policies_array[@]}"
    else
        echo "获取客户管理策略列表失败"
    fi
    
    echo "IAM检查完成"
    safe_log "IAM检查完成" "$LOG_FILE"
}

# 其他服务检查函数（简化版本，专注于IAM优化）
check_s3_policies() {
    echo -e "${BLUE}2. 检查S3存储桶策略${NC}"
    update_check_count
    
    local checked_buckets=0
    while read -r bucket; do
        if [ -n "$bucket" ]; then
            ((checked_buckets++))
            log_check_detail "S3" "Bucket:$bucket" "检查中" "检查存储桶策略"
            
            bucket_policy=$(aws s3api get-bucket-policy --bucket "$bucket" --query 'Policy' --output text 2>/dev/null || echo "")
            if [ -n "$bucket_policy" ] && [ "$bucket_policy" != "None" ]; then
                if check_org_keywords "$bucket_policy"; then
                    log_issue "S3" "Bucket:$bucket" "存储桶策略包含组织相关配置" "$bucket_policy"
                    log_check_detail "S3" "Bucket:$bucket" "有问题" "存储桶策略包含组织相关配置"
                    log_org_finding "S3 Bucket Policy" "$bucket" "$bucket_policy"
                else
                    log_check_detail "S3" "Bucket:$bucket" "正常" "存储桶策略无组织相关配置"
                fi
            else
                log_check_detail "S3" "Bucket:$bucket" "无策略" "存储桶无策略配置"
            fi
        fi
    done < <(aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n')
    
    echo "S3检查完成: 存储桶($checked_buckets)"
    safe_log "S3检查完成: 存储桶($checked_buckets)" "$LOG_FILE"
}

# 主执行流程
echo -e "${YELLOW}开始检查各服务策略 (优化版本 v2)...${NC}"
safe_log "开始检查各服务策略 (优化版本 v2) - $(date)" "$LOG_FILE"
echo ""

# 记录开始时间
start_time=$(date +%s)

# 执行检查
check_iam_policies_optimized
check_s3_policies

# 记录结束时间
end_time=$(date +%s)
duration=$((end_time - start_time))

echo ""
echo -e "${GREEN}=== 检查完成 ===${NC}"
echo "检查耗时: ${duration}秒"
safe_log "检查完成 - $(date), 耗时: ${duration}秒" "$LOG_FILE"

# 显示总结
total_checks=$(jq -r '.summary.total_checks' "$ISSUES_FILE")
issues_found=$(jq -r '.summary.issues_found' "$ISSUES_FILE")

echo "总检查项目: $total_checks"
echo "发现问题: $issues_found"
safe_log "总检查项目: $total_checks, 发现问题: $issues_found" "$LOG_FILE"

# 检查组织相关发现文件的内容
org_findings_count=$(grep -c "^[A-Z].*:" "$ORG_FINDINGS_FILE" 2>/dev/null || echo "0")

if [ "$issues_found" -gt 0 ]; then
    echo -e "${RED}发现 $issues_found 个与组织相关的策略配置问题${NC}"
    echo "详细信息请查看:"
    echo "- 主日志文件: $LOG_FILE"
    echo "- 详细日志文件: $DETAILED_LOG_FILE"
    echo "- JSON报告: $ISSUES_FILE"
    echo -e "${YELLOW}- 组织相关发现详情: $ORG_FINDINGS_FILE${NC}"
    
    if [ "$org_findings_count" -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}组织相关发现摘要:${NC}"
        echo "  - 共发现 $org_findings_count 个包含组织相关配置的资源"
        echo "  - 详细策略内容已保存到: $ORG_FINDINGS_FILE"
    fi
else
    echo -e "${GREEN}未发现组织相关的策略配置问题${NC}"
    echo -e "${GREEN}账号可以安全迁移${NC}"
fi

echo ""
echo "检查完成时间: $(date)"
echo "检查耗时: ${duration}秒"
echo ""
echo "文件输出位置:"
echo "- 主日志: $LOG_FILE"
echo "- 详细日志: $DETAILED_LOG_FILE"
echo "- JSON报告: $ISSUES_FILE"
if [ "$org_findings_count" -gt 0 ]; then
    echo -e "${YELLOW}- 组织相关发现: $ORG_FINDINGS_FILE (包含 $org_findings_count 个发现)${NC}"
else
    echo "- 组织相关发现: $ORG_FINDINGS_FILE (无发现)"
fi

# 在组织相关发现文件末尾添加总结
echo "" >> "$ORG_FINDINGS_FILE"
echo "========================================" >> "$ORG_FINDINGS_FILE"
echo "检查总结:" >> "$ORG_FINDINGS_FILE"
echo "- 检查完成时间: $(date)" >> "$ORG_FINDINGS_FILE"
echo "- 检查耗时: ${duration}秒" >> "$ORG_FINDINGS_FILE"
echo "- 总检查项目: $total_checks" >> "$ORG_FINDINGS_FILE"
echo "- 发现问题: $issues_found" >> "$ORG_FINDINGS_FILE"
echo "- 组织相关发现: $org_findings_count" >> "$ORG_FINDINGS_FILE"

# 清理临时文件
rm -rf "$TEMP_DIR"
