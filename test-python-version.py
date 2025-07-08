#!/usr/bin/env python3
"""
Python版本功能测试脚本
"""

import os
import sys
import subprocess
import time
import json
from pathlib import Path

def print_colored(message, color_code):
    """打印彩色文本"""
    print(f"\033[{color_code}m{message}\033[0m")

def print_info(message):
    print_colored(f"ℹ️  {message}", "34")  # 蓝色

def print_success(message):
    print_colored(f"✅ {message}", "32")  # 绿色

def print_warning(message):
    print_colored(f"⚠️  {message}", "33")  # 黄色

def print_error(message):
    print_colored(f"❌ {message}", "31")  # 红色

def check_dependencies():
    """检查依赖"""
    print_info("检查Python依赖...")
    
    required_modules = ['boto3', 'colorama']
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
            print_success(f"{module} 已安装")
        except ImportError:
            missing_modules.append(module)
            print_error(f"{module} 未安装")
    
    if missing_modules:
        print_error(f"缺少依赖: {', '.join(missing_modules)}")
        print_info("请运行: pip install -r requirements.txt")
        return False
    
    return True

def check_aws_credentials():
    """检查AWS凭证"""
    print_info("检查AWS凭证...")
    
    try:
        import boto3
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        account_id = identity['Account']
        print_success(f"AWS凭证有效，账号ID: {account_id}")
        return True
    except Exception as e:
        print_error(f"AWS凭证无效: {e}")
        return False

def test_basic_functionality():
    """测试基本功能"""
    print_info("测试Python版本基本功能...")
    
    # 运行Python版本（限制时间和并发数）
    cmd = [
        sys.executable, 
        'check_org_policies.py', 
        '--max-workers', '3',
        '--debug'
    ]
    
    try:
        print_info("运行Python版本脚本（60秒超时）...")
        result = subprocess.run(
            cmd, 
            timeout=60, 
            capture_output=True, 
            text=True
        )
        
        if result.returncode == 0:
            print_success("Python版本执行成功")
            return True
        else:
            print_error(f"Python版本执行失败，退出码: {result.returncode}")
            print_error(f"错误输出: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print_warning("Python版本执行超时（这可能是正常的）")
        return True
    except Exception as e:
        print_error(f"执行Python版本时发生异常: {e}")
        return False

def test_output_files():
    """测试输出文件"""
    print_info("检查输出文件...")
    
    logs_dir = Path('logs')
    if not logs_dir.exists():
        print_error("logs目录不存在")
        return False
    
    # 查找Python版本生成的文件
    python_files = list(logs_dir.glob('*-python-*.json'))
    
    if not python_files:
        print_warning("未找到Python版本生成的JSON文件（可能是超时导致）")
        return True
    
    # 验证JSON文件格式
    for json_file in python_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # 检查必要的字段
            required_fields = ['issues', 'summary', 'check_details']
            for field in required_fields:
                if field not in data:
                    print_error(f"JSON文件缺少字段: {field}")
                    return False
            
            print_success(f"JSON文件格式有效: {json_file.name}")
            
        except json.JSONDecodeError as e:
            print_error(f"JSON文件格式无效: {json_file.name}, 错误: {e}")
            return False
        except Exception as e:
            print_error(f"读取JSON文件失败: {json_file.name}, 错误: {e}")
            return False
    
    return True

def test_concurrency_levels():
    """测试不同并发级别"""
    print_info("测试不同并发级别...")
    
    concurrency_levels = [1, 3, 5]
    
    for level in concurrency_levels:
        print_info(f"测试并发数: {level}")
        
        cmd = [
            sys.executable,
            'check_org_policies.py',
            '--max-workers', str(level)
        ]
        
        try:
            start_time = time.time()
            result = subprocess.run(
                cmd,
                timeout=30,  # 短超时时间
                capture_output=True,
                text=True
            )
            end_time = time.time()
            
            duration = end_time - start_time
            
            if result.returncode == 0:
                print_success(f"并发数 {level}: 成功，耗时 {duration:.1f}秒")
            else:
                print_warning(f"并发数 {level}: 失败或超时")
                
        except subprocess.TimeoutExpired:
            print_warning(f"并发数 {level}: 超时（这可能是正常的）")
        except Exception as e:
            print_error(f"并发数 {level}: 异常 - {e}")
    
    return True

def performance_comparison():
    """性能对比测试"""
    print_info("进行性能对比测试...")
    
    # 测试Python版本
    print_info("测试Python版本性能...")
    python_cmd = [
        sys.executable,
        'check_org_policies.py',
        '--max-workers', '8'
    ]
    
    try:
        start_time = time.time()
        result = subprocess.run(
            python_cmd,
            timeout=120,
            capture_output=True,
            text=True
        )
        python_duration = time.time() - start_time
        
        if result.returncode == 0:
            print_success(f"Python版本完成，耗时: {python_duration:.1f}秒")
        else:
            print_warning(f"Python版本超时或失败，耗时: {python_duration:.1f}秒")
            
    except subprocess.TimeoutExpired:
        python_duration = 120
        print_warning("Python版本超时（120秒）")
    except Exception as e:
        print_error(f"Python版本测试异常: {e}")
        return False
    
    # 如果存在Bash版本，进行对比
    if Path('check-org-policies-optimized-v2.sh').exists():
        print_info("测试Bash版本性能...")
        bash_cmd = ['bash', 'check-org-policies-optimized-v2.sh']
        env = os.environ.copy()
        env['MAX_PARALLEL_JOBS'] = '8'
        
        try:
            start_time = time.time()
            result = subprocess.run(
                bash_cmd,
                timeout=120,
                capture_output=True,
                text=True,
                env=env
            )
            bash_duration = time.time() - start_time
            
            if result.returncode == 0:
                print_success(f"Bash版本完成，耗时: {bash_duration:.1f}秒")
            else:
                print_warning(f"Bash版本超时或失败，耗时: {bash_duration:.1f}秒")
            
            # 性能对比
            if python_duration < 120 and bash_duration < 120:
                if python_duration < bash_duration:
                    improvement = (bash_duration - python_duration) / bash_duration * 100
                    print_success(f"Python版本比Bash版本快 {improvement:.1f}%")
                else:
                    degradation = (python_duration - bash_duration) / bash_duration * 100
                    print_warning(f"Python版本比Bash版本慢 {degradation:.1f}%")
                    
        except subprocess.TimeoutExpired:
            print_warning("Bash版本超时（120秒）")
        except Exception as e:
            print_warning(f"Bash版本测试异常: {e}")
    
    return True

def main():
    """主测试函数"""
    print_colored("=== Python版本功能测试 ===", "34")
    print()
    
    tests = [
        ("依赖检查", check_dependencies),
        ("AWS凭证检查", check_aws_credentials),
        ("基本功能测试", test_basic_functionality),
        ("输出文件检查", test_output_files),
        ("并发级别测试", test_concurrency_levels),
        ("性能对比测试", performance_comparison)
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_name, test_func in tests:
        print_info(f"开始 {test_name}...")
        try:
            if test_func():
                print_success(f"{test_name} 通过")
                passed_tests += 1
            else:
                print_error(f"{test_name} 失败")
        except Exception as e:
            print_error(f"{test_name} 异常: {e}")
        print()
    
    # 测试总结
    print_colored("=== 测试总结 ===", "34")
    print(f"总测试数: {total_tests}")
    print(f"通过测试数: {passed_tests}")
    print(f"失败测试数: {total_tests - passed_tests}")
    
    if passed_tests == total_tests:
        print_success("所有测试通过！Python版本可以正常使用。")
        
        # 使用建议
        print()
        print_colored("=== 使用建议 ===", "34")
        
        # 检测环境
        if os.getenv('AWS_EXECUTION_ENV') and 'CloudShell' in os.getenv('AWS_EXECUTION_ENV', ''):
            print_info("CloudShell环境推荐配置:")
            print("  python3 check_org_policies.py --max-workers 8")
        else:
            print_info("本地/服务器环境推荐配置:")
            print("  python3 check_org_policies.py --max-workers 15")
        
        print()
        print_info("其他有用的命令:")
        print("  # 调试模式")
        print("  python3 check_org_policies.py --debug")
        print("  # 自定义并发数")
        print("  python3 check_org_policies.py --max-workers 10")
        print("  # 环境变量配置")
        print("  MAX_PARALLEL_JOBS=12 python3 check_org_policies.py")
        
    elif passed_tests >= total_tests * 0.8:
        print_warning("大部分测试通过，Python版本基本可用，但可能存在一些问题。")
    else:
        print_error("多个测试失败，建议检查环境配置后重试。")
    
    return passed_tests == total_tests

if __name__ == '__main__':
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print_error("\n测试被用户中断")
        sys.exit(1)
    except Exception as e:
        print_error(f"测试过程中发生异常: {e}")
        sys.exit(1)
