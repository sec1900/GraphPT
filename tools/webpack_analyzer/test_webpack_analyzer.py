#!/usr/bin/env python3
"""webpack_analyzer 工具测试脚本"""

import subprocess
import sys
import json

def test_webpack_detection():
    """测试 Webpack bundle 检测"""
    print("=" * 60)
    print("Test 1: Webpack Bundle Detection")
    print("=" * 60)

    # 创建一个简单的模拟 Webpack bundle
    test_js = '''
    (window["webpackJsonp"] = window["webpackJsonp"] || []).push([[0], {
        "./src/api.js": function(module, exports) {
            function login(username, password) {
                return axios.post("/api/v1/user/login", {
                    username: username,
                    password: password
                });
            }

            function getUserInfo() {
                return axios.get("/api/v1/user/info");
            }

            function updateProfile(data) {
                return fetch("/api/v1/user/profile", {
                    method: "PUT",
                    body: JSON.stringify(data)
                });
            }

            function searchUsers(query) {
                return axios.get("/api/v2/users/search?q=" + query);
            }
        }
    }]);
    '''

    # 保存为临时文件
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False, encoding='utf-8') as f:
        f.write(test_js)
        temp_path = f.name

    try:
        # 使用 file:// 协议（webpack_analyzer 需要修改以支持本地文件）
        # 这里我们直接测试核心函数
        print(f"Test bundle saved to: {temp_path}")

        # 导入核心函数测试
        sys.path.insert(0, 'tools/webpack_analyzer')
        import webpack_analyzer

        with open(temp_path, 'rb') as f:
            content = f.read()

        # 测试检测
        is_webpack = webpack_analyzer.is_webpack_bundle(content)
        print(f"[OK] Is Webpack bundle: {is_webpack}")
        assert is_webpack, "Should detect as Webpack bundle"

        # 测试 API 提取
        findings, frameworks = webpack_analyzer.analyze_webpack_bundle(content, "test.js")
        print(f"[OK] Found {len(findings)} API endpoints")
        assert "webpack" in frameworks

        for finding in findings:
            print(f"  - {finding['method']} {finding['path']}")
            if finding['params']:
                print(f"    Params: {', '.join(finding['params'])}")

        # 验证结果
        paths = [f['path'] for f in findings]
        assert "/api/v1/user/login" in paths, "Should find login API"
        assert "/api/v1/user/info" in paths, "Should find getUserInfo API"
        assert "/api/v1/user/profile" in paths, "Should find profile API"

        # 验证参数
        login_api = next(f for f in findings if f['path'] == "/api/v1/user/login")
        assert 'username' in login_api['params'], "Should extract username param"
        assert 'password' in login_api['params'], "Should extract password param"

        print("\n[OK] All tests passed!")

    finally:
        os.unlink(temp_path)

def test_adapter():
    """测试适配器"""
    print("\n" + "=" * 60)
    print("Test 2: Adapter Parse Output")
    print("=" * 60)

    sys.path.insert(0, 'tools/webpack_analyzer')
    from adapter import WebpackAnalyzerAdapter

    # 模拟工具输出
    output = '''{"type":"http_endpoint","roles":["api"],"method":"POST","path":"/api/user/login","params":["username","password"],"source_url":"https://example.com/app.js"}
{"type":"http_endpoint","roles":["api"],"method":"GET","path":"/api/user/info","params":[],"source_url":"https://example.com/app.js"}'''

    adapter = WebpackAnalyzerAdapter()
    parsed = adapter.parse(output, asset_id="test-asset")

    print(f"[OK] Parsed {len(parsed)} endpoints")
    for api in parsed:
        print(f"  - {api['method']} {api['url']}")

    assert len(parsed) == 2, "Should parse 2 endpoints"
    assert parsed[0]['type'] == 'http_endpoint'
    assert parsed[0]['method'] == 'POST', "First endpoint should be POST"
    assert len(parsed[0]['params']) == 2, "Login should have 2 params"

    print("\n[OK] Adapter test passed!")

if __name__ == '__main__':
    try:
        test_webpack_detection()
        # test_adapter()  # 跳过 adapter 测试，需要完整 GraphPT 环境
        print("\n" + "=" * 60)
        print("Core tests completed successfully!")
        print("=" * 60)
    except Exception as e:
        print(f"\n[FAIL] Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
