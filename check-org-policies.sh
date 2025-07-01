#!/bin/bash

# AWS账号组织策略检查脚本
# 用于检查账号中所有服务的策略是否包含组织相关配置

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志文件
LOG_FILE="org-policy-check-$(date +%Y%m%d-%H%M%S).log"
ISSUES_FILE="org-policy-issues-$(date +%Y%m%d-%H%M%S).json"

echo -e "${BLUE}=== AWS账号组织策略检查工具 ===${NC}"
echo "日志文件: $LOG_FILE"
echo "问题报告: $ISSUES_FILE"
echo ""

# 初始化问题报告文件
echo '{"issues": [], "summary": {"total_checks": 0, "issues_found": 0}}' > "$ISSUES_FILE"

# 记录问题的函数
log_issue() {
    local service="$1"
    local resource="$2"
    local issue="$3"
    local details="$4"
    
    echo -e "${RED}[问题] $service - $resource: $issue${NC}"
    echo "$service - $resource: $issue - $details" >> "$LOG_FILE"
    
    # 添加到JSON报告
    jq --arg service "$service" --arg resource "$resource" --arg issue "$issue" --arg details "$details" \
       '.issues += [{"service": $service, "resource": $resource, "issue": $issue, "details": $details}] | .summary.issues_found += 1' \
       "$ISSUES_FILE" > tmp.json && mv tmp.json "$ISSUES_FILE"
}

# 更新检查计数
update_check_count() {
    jq '.summary.total_checks += 1' "$ISSUES_FILE" > tmp.json && mv tmp.json "$ISSUES_FILE"
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

echo -e "${YELLOW}开始检查各服务策略...${NC}"

# 1. 检查IAM策略
echo -e "${BLUE}1. 检查IAM策略${NC}"
update_check_count

# 检查IAM角色
echo "检查IAM角色..."
aws iam list-roles --query 'Roles[].RoleName' --output text 2>/dev/null | tr '\t' '\n' | while read -r role; do
    if [ -n "$role" ]; then
        policy_doc=$(aws iam get-role --role-name "$role" --query 'Role.AssumeRolePolicyDocument' --output text 2>/dev/null || echo "")
        if check_org_keywords "$policy_doc"; then
            log_issue "IAM" "Role:$role" "包含组织相关配置" "$policy_doc"
        fi
        
        # 检查附加的策略
        aws iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null | tr '\t' '\n' | while read -r policy_arn; do
            if [ -n "$policy_arn" ]; then
                version_id=$(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text 2>/dev/null || echo "")
                if [ -n "$version_id" ]; then
                    policy_content=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query 'PolicyVersion.Document' --output text 2>/dev/null || echo "")
                    if check_org_keywords "$policy_content"; then
                        log_issue "IAM" "Policy:$policy_arn" "包含组织相关配置" "$policy_content"
                    fi
                fi
            fi
        done
    fi
done

# 检查IAM用户
echo "检查IAM用户..."
aws iam list-users --query 'Users[].UserName' --output text 2>/dev/null | tr '\t' '\n' | while read -r user; do
    if [ -n "$user" ]; then
        aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null | tr '\t' '\n' | while read -r policy_arn; do
            if [ -n "$policy_arn" ]; then
                version_id=$(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text 2>/dev/null || echo "")
                if [ -n "$version_id" ]; then
                    policy_content=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query 'PolicyVersion.Document' --output text 2>/dev/null || echo "")
                    if check_org_keywords "$policy_content"; then
                        log_issue "IAM" "UserPolicy:$user->$policy_arn" "包含组织相关配置" "$policy_content"
                    fi
                fi
            fi
        done
    fi
done

# 2. 检查S3存储桶策略
echo -e "${BLUE}2. 检查S3存储桶策略${NC}"
update_check_count

aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n' | while read -r bucket; do
    if [ -n "$bucket" ]; then
        bucket_policy=$(aws s3api get-bucket-policy --bucket "$bucket" --query 'Policy' --output text 2>/dev/null || echo "")
        if [ -n "$bucket_policy" ] && [ "$bucket_policy" != "None" ]; then
            if check_org_keywords "$bucket_policy"; then
                log_issue "S3" "Bucket:$bucket" "存储桶策略包含组织相关配置" "$bucket_policy"
            fi
        fi
    fi
done

# 3. 检查KMS密钥策略
echo -e "${BLUE}3. 检查KMS密钥策略${NC}"
update_check_count

aws kms list-keys --query 'Keys[].KeyId' --output text 2>/dev/null | tr '\t' '\n' | while read -r key_id; do
    if [ -n "$key_id" ]; then
        key_policy=$(aws kms get-key-policy --key-id "$key_id" --policy-name default --query 'Policy' --output text 2>/dev/null || echo "")
        if [ -n "$key_policy" ]; then
            if check_org_keywords "$key_policy"; then
                log_issue "KMS" "Key:$key_id" "密钥策略包含组织相关配置" "$key_policy"
            fi
        fi
    fi
done

# 4. 检查Lambda函数资源策略
echo -e "${BLUE}4. 检查Lambda函数资源策略${NC}"
update_check_count

aws lambda list-functions --query 'Functions[].FunctionName' --output text 2>/dev/null | tr '\t' '\n' | while read -r function_name; do
    if [ -n "$function_name" ]; then
        function_policy=$(aws lambda get-policy --function-name "$function_name" --query 'Policy' --output text 2>/dev/null || echo "")
        if [ -n "$function_policy" ] && [ "$function_policy" != "None" ]; then
            if check_org_keywords "$function_policy"; then
                log_issue "Lambda" "Function:$function_name" "函数策略包含组织相关配置" "$function_policy"
            fi
        fi
    fi
done

# 5. 检查SNS主题策略
echo -e "${BLUE}5. 检查SNS主题策略${NC}"
update_check_count

aws sns list-topics --query 'Topics[].TopicArn' --output text 2>/dev/null | tr '\t' '\n' | while read -r topic_arn; do
    if [ -n "$topic_arn" ]; then
        topic_policy=$(aws sns get-topic-attributes --topic-arn "$topic_arn" --query 'Attributes.Policy' --output text 2>/dev/null || echo "")
        if [ -n "$topic_policy" ] && [ "$topic_policy" != "None" ]; then
            if check_org_keywords "$topic_policy"; then
                log_issue "SNS" "Topic:$topic_arn" "主题策略包含组织相关配置" "$topic_policy"
            fi
        fi
    fi
done

# 6. 检查SQS队列策略
echo -e "${BLUE}6. 检查SQS队列策略${NC}"
update_check_count

aws sqs list-queues --query 'QueueUrls[]' --output text 2>/dev/null | tr '\t' '\n' | while read -r queue_url; do
    if [ -n "$queue_url" ]; then
        queue_policy=$(aws sqs get-queue-attributes --queue-url "$queue_url" --attribute-names Policy --query 'Attributes.Policy' --output text 2>/dev/null || echo "")
        if [ -n "$queue_policy" ] && [ "$queue_policy" != "None" ]; then
            if check_org_keywords "$queue_policy"; then
                log_issue "SQS" "Queue:$queue_url" "队列策略包含组织相关配置" "$queue_policy"
            fi
        fi
    fi
done

# 7. 检查ECR仓库策略
echo -e "${BLUE}7. 检查ECR仓库策略${NC}"
update_check_count

aws ecr describe-repositories --query 'repositories[].repositoryName' --output text 2>/dev/null | tr '\t' '\n' | while read -r repo_name; do
    if [ -n "$repo_name" ]; then
        repo_policy=$(aws ecr get-repository-policy --repository-name "$repo_name" --query 'policyText' --output text 2>/dev/null || echo "")
        if [ -n "$repo_policy" ] && [ "$repo_policy" != "None" ]; then
            if check_org_keywords "$repo_policy"; then
                log_issue "ECR" "Repository:$repo_name" "仓库策略包含组织相关配置" "$repo_policy"
            fi
        fi
    fi
done

# 8. 检查Secrets Manager资源策略
echo -e "${BLUE}8. 检查Secrets Manager资源策略${NC}"
update_check_count

aws secretsmanager list-secrets --query 'SecretList[].ARN' --output text 2>/dev/null | tr '\t' '\n' | while read -r secret_arn; do
    if [ -n "$secret_arn" ]; then
        secret_policy=$(aws secretsmanager get-resource-policy --secret-id "$secret_arn" --query 'ResourcePolicy' --output text 2>/dev/null || echo "")
        if [ -n "$secret_policy" ] && [ "$secret_policy" != "None" ]; then
            if check_org_keywords "$secret_policy"; then
                log_issue "SecretsManager" "Secret:$secret_arn" "密钥策略包含组织相关配置" "$secret_policy"
            fi
        fi
    fi
done

# 9. 检查CloudWatch Logs资源策略
echo -e "${BLUE}9. 检查CloudWatch Logs资源策略${NC}"
update_check_count

aws logs describe-resource-policies --query 'resourcePolicies[].{PolicyName:policyName,PolicyDocument:policyDocument}' --output json 2>/dev/null | jq -r '.[] | "\(.PolicyName)|\(.PolicyDocument)"' | while IFS='|' read -r policy_name policy_doc; do
    if [ -n "$policy_doc" ]; then
        if check_org_keywords "$policy_doc"; then
            log_issue "CloudWatchLogs" "ResourcePolicy:$policy_name" "资源策略包含组织相关配置" "$policy_doc"
        fi
    fi
done

# 10. 检查API Gateway资源策略
echo -e "${BLUE}10. 检查API Gateway资源策略${NC}"
update_check_count

# REST APIs
aws apigateway get-rest-apis --query 'items[].id' --output text 2>/dev/null | tr '\t' '\n' | while read -r api_id; do
    if [ -n "$api_id" ]; then
        api_policy=$(aws apigateway get-rest-api --rest-api-id "$api_id" --query 'policy' --output text 2>/dev/null || echo "")
        if [ -n "$api_policy" ] && [ "$api_policy" != "None" ]; then
            if check_org_keywords "$api_policy"; then
                log_issue "APIGateway" "RestAPI:$api_id" "API策略包含组织相关配置" "$api_policy"
            fi
        fi
    fi
done

echo ""
echo -e "${GREEN}=== 检查完成 ===${NC}"

# 显示总结
total_checks=$(jq -r '.summary.total_checks' "$ISSUES_FILE")
issues_found=$(jq -r '.summary.issues_found' "$ISSUES_FILE")

echo "总检查项目: $total_checks"
echo "发现问题: $issues_found"

if [ "$issues_found" -gt 0 ]; then
    echo -e "${RED}发现 $issues_found 个与组织相关的策略配置问题${NC}"
    echo "详细信息请查看:"
    echo "- 日志文件: $LOG_FILE"
    echo "- JSON报告: $ISSUES_FILE"
    echo ""
    echo -e "${YELLOW}建议在迁移账号前修复这些问题${NC}"
else
    echo -e "${GREEN}未发现组织相关的策略配置问题${NC}"
    echo -e "${GREEN}账号可以安全迁移${NC}"
fi

echo ""
echo "检查完成时间: $(date)"
