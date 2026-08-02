#!/usr/bin/env python3
"""集成测试：验证问题 4 修复 - Adapter 错误处理机制。"""
import sys
import time
sys.path.insert(0, r'E:\GraphPT')

from graphpt.collector.pipeline import PipelineExecutor
from graphpt.collector.neo4j_client import get_graph_writer

# 清理旧数据
print("清理测试数据...")
writer = get_graph_writer()
writer.execute_write(
    "MATCH (n) WHERE n.id STARTS WITH 'test-adapter-' DETACH DELETE n",
    {}
)

# 创建测试资产
asset_id = "test-adapter-verify"
print(f"创建测试资产: {asset_id}")
writer.execute_write(
    """
    MERGE (a:Asset {id: $aid})
    SET a.name = $name, a.created_at = datetime()
    """,
    {"aid": asset_id, "name": "Adapter Test Verify"}
)

# 添加测试域名（corrupt.test - 会触发 Adapter 失败）
print("添加测试域名: corrupt.test")
writer.execute_write(
    """
    MATCH (a:Asset {id: $aid})
    MERGE (r:RootDomain {id: $rid})
    SET r.domain = $domain, r.asset_id = $aid
    MERGE (a)-[:OWNS]->(r)
    """,
    {"aid": asset_id, "rid": f"{asset_id}:corrupt.test", "domain": "corrupt.test"}
)

# 创建 PipelineExecutor 并运行 test_adapter
print("\n开始扫描...")
executor = PipelineExecutor(asset_id=asset_id)

# 手动触发 test_adapter 工具扫描 corrupt.test
try:
    executor.run_layer(layer=1, tools=["test_adapter"])
    print("扫描完成")
except Exception as e:
    print(f"扫描出错: {e}")

time.sleep(2)

# 验证结果
print("\n" + "="*70)
print("验证结果")
print("="*70)

# 1. 检查 corrupt.test 是否被标记为已扫描
print("\n[1] 检查目标是否被标记为已扫描...")
result = writer.execute_read(
    """
    MATCH (r:RootDomain {domain: 'corrupt.test'})
    RETURN r.scanned_by_test_adapter AS scanned,
           r.test_adapter_findings_count AS count
    """,
    {}
)
if result:
    scanned = result[0].get("scanned")
    count = result[0].get("count")
    print(f"  scanned_by_test_adapter: {scanned}")
    print(f"  findings_count: {count}")
    if scanned:
        print("  [OK] 目标已标记为已扫描（即使 Adapter 失败）")
    else:
        print("  [X] 目标未标记为已扫描 - 修复失败！")
else:
    print("  [X] 未找到域名节点")

# 2. 检查错误记录是否包含日志路径
print("\n[2] 检查错误记录...")
from graphpt.common.redis_client import get_redis
redis = get_redis()
error_key = f"errors:{asset_id}"
errors = redis.lrange(error_key, 0, -1)

if errors:
    import json
    for err_json in errors:
        err = json.loads(err_json)
        if err.get("tool") == "test_adapter" and err.get("kind") == "adapter_error":
            print(f"  工具: {err.get('tool')}")
            print(f"  目标: {err.get('target')}")
            print(f"  错误类型: {err.get('kind')}")
            print(f"  错误信息: {err.get('message')[:80]}...")
            log_file = err.get('log_file')
            if log_file:
                print(f"  日志文件: {log_file}")
                print("  [OK] 日志路径已保存到错误记录")
            else:
                print("  [X] 日志路径未保存 - 修复失败！")
            break
    else:
        print("  [X] 未找到 test_adapter 的 adapter_error 错误")
else:
    print("  [X] 没有错误记录 - 修复可能失败！")

print("\n" + "="*70)
print("测试完成")
print("="*70)
