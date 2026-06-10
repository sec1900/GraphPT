// Demo seed data for a fully visible GraphPT attack-surface chain.
// It is intentionally idempotent: rerunning it MERGEs the same demo nodes.
// No existing assets are deleted.

WITH "2026-06-10T22:45:00Z" AS now
MERGE (a:Asset {id: "test"})
SET a.name = "test",
    a.created_at = coalesce(a.created_at, now),
    a.updated_at = now,
    a.demo = true,
    a.sources = ["demo-seed"]
WITH a, now
UNWIND [
  {
    id: "root:demo-corp.test",
    value: "demo-corp.test",
    icp: "DEMO-ICP-2026-0001",
    website: "https://www.demo-corp.test/",
    website_name: "Demo Corp Portal",
    sources: ["enscan", "demo-seed"]
  },
  {
    id: "root:demo-payments.test",
    value: "demo-payments.test",
    icp: "DEMO-ICP-2026-0002",
    website: "https://pay.demo-payments.test/",
    website_name: "Demo Payments",
    sources: ["enscan", "demo-seed"]
  }
] AS row
MERGE (r:RootDomain {id: row.id})
SET r.value = row.value,
    r.icp = row.icp,
    r.website = row.website,
    r.website_name = row.website_name,
    r.sources = row.sources,
    r.source = row.sources[0],
    r.created_at = coalesce(r.created_at, now),
    r.last_seen_at = now,
    r.demo = true
MERGE (a)-[:HAS_ROOT]->(r);

WITH "2026-06-10T22:45:00Z" AS now
UNWIND [
  {id: "icp:DEMO-ICP-2026-0001", number: "DEMO-ICP-2026-0001", company_name: "Demo Corp"},
  {id: "icp:DEMO-ICP-2026-0002", number: "DEMO-ICP-2026-0002", company_name: "Demo Payments"}
] AS row
MATCH (a:Asset {id: "test"})
MERGE (icp:ICPRecord {id: row.id})
SET icp.number = row.number,
    icp.company_name = row.company_name,
    icp.sources = ["enscan", "demo-seed"],
    icp.created_at = coalesce(icp.created_at, now),
    icp.last_seen_at = now,
    icp.demo = true
MERGE (a)-[:HAS_ICP]->(icp);

MATCH (icp:ICPRecord {id: "icp:DEMO-ICP-2026-0001"})
MATCH (r:RootDomain {id: "root:demo-corp.test"})
MERGE (icp)-[:COVERS]->(r);

MATCH (icp:ICPRecord {id: "icp:DEMO-ICP-2026-0002"})
MATCH (r:RootDomain {id: "root:demo-payments.test"})
MERGE (icp)-[:COVERS]->(r);

WITH "2026-06-10T22:45:00Z" AS now
UNWIND [
  {
    id: "sub:www.demo-corp.test",
    value: "www.demo-corp.test",
    root_id: "root:demo-corp.test",
    source: "subfinder",
    sources: ["subfinder", "crt", "demo-seed"],
    created_at: "2026-06-10T21:59:00Z"
  },
  {
    id: "sub:api.demo-corp.test",
    value: "api.demo-corp.test",
    root_id: "root:demo-corp.test",
    source: "subfinder",
    sources: ["subfinder", "httpx", "demo-seed"],
    created_at: "2026-06-10T22:01:00Z"
  },
  {
    id: "sub:admin.demo-corp.test",
    value: "admin.demo-corp.test",
    root_id: "root:demo-corp.test",
    source: "crt",
    sources: ["crt", "dnsx", "demo-seed"],
    created_at: "2026-06-10T22:04:00Z"
  },
  {
    id: "sub:cdn.demo-corp.test",
    value: "cdn.demo-corp.test",
    root_id: "root:demo-corp.test",
    source: "crt",
    sources: ["crt", "demo-seed"],
    created_at: "2026-06-10T22:06:00Z"
  },
  {
    id: "sub:pay.demo-payments.test",
    value: "pay.demo-payments.test",
    root_id: "root:demo-payments.test",
    source: "subfinder",
    sources: ["subfinder", "dnsx", "demo-seed"],
    created_at: "2026-06-10T22:08:00Z"
  },
  {
    id: "sub:auth.demo-payments.test",
    value: "auth.demo-payments.test",
    root_id: "root:demo-payments.test",
    source: "crt",
    sources: ["crt", "subfinder", "demo-seed"],
    created_at: "2026-06-10T22:10:00Z"
  }
] AS row
MATCH (r:RootDomain {id: row.root_id})
MERGE (s:Subdomain {id: row.id})
SET s.value = row.value,
    s.source = row.source,
    s.sources = row.sources,
    s.created_at = coalesce(s.created_at, row.created_at),
    s.last_seen_at = now,
    s.demo = true
MERGE (r)-[:HAS_SUB]->(s);

WITH "2026-06-10T22:45:00Z" AS now
UNWIND [
  {id: "ip:203.0.113.10", value: "203.0.113.10", sources: ["dnsx", "demo-seed"]},
  {id: "ip:203.0.113.20", value: "203.0.113.20", sources: ["dnsx", "demo-seed"]},
  {id: "ip:203.0.113.30", value: "203.0.113.30", sources: ["dnsx", "demo-seed"]},
  {id: "ip:198.51.100.15", value: "198.51.100.15", sources: ["dnsx", "demo-seed"]},
  {id: "ip:192.0.2.50", value: "192.0.2.50", sources: ["manual", "demo-seed"]}
] AS row
MERGE (ip:IP {id: row.id})
SET ip.value = row.value,
    ip.sources = row.sources,
    ip.created_at = coalesce(ip.created_at, now),
    ip.last_seen_at = now,
    ip.demo = true;

WITH "2026-06-10T22:45:00Z" AS now
UNWIND [
  {sub_id: "sub:www.demo-corp.test", ip_id: "ip:203.0.113.10", sources: ["dnsx", "demo-seed"]},
  {sub_id: "sub:api.demo-corp.test", ip_id: "ip:203.0.113.10", sources: ["dnsx", "demo-seed"]},
  {sub_id: "sub:admin.demo-corp.test", ip_id: "ip:203.0.113.20", sources: ["dnsx", "demo-seed"]},
  {sub_id: "sub:cdn.demo-corp.test", ip_id: "ip:203.0.113.30", sources: ["dnsx", "demo-seed"]},
  {sub_id: "sub:pay.demo-payments.test", ip_id: "ip:198.51.100.15", sources: ["dnsx", "demo-seed"]},
  {sub_id: "sub:auth.demo-payments.test", ip_id: "ip:198.51.100.15", sources: ["dnsx", "demo-seed"]}
] AS row
MATCH (s:Subdomain {id: row.sub_id})
MATCH (ip:IP {id: row.ip_id})
MERGE (s)-[rel:RESOLVES_TO]->(ip)
SET rel.sources = row.sources,
    rel.first_seen = coalesce(rel.first_seen, now),
    rel.last_seen = now;

MATCH (a:Asset {id: "test"})
MATCH (ip:IP {id: "ip:192.0.2.50"})
MERGE (a)-[:HAS_IP]->(ip);

WITH "2026-06-10T22:45:00Z" AS now
UNWIND [
  {id: "port:ip:203.0.113.10:80/tcp", ip_id: "ip:203.0.113.10", number: 80, protocol: "tcp", service_id: "svc:ip:203.0.113.10:80/tcp", service: "nginx"},
  {id: "port:ip:203.0.113.10:443/tcp", ip_id: "ip:203.0.113.10", number: 443, protocol: "tcp", service_id: "svc:ip:203.0.113.10:443/tcp", service: "nginx"},
  {id: "port:ip:203.0.113.20:22/tcp", ip_id: "ip:203.0.113.20", number: 22, protocol: "tcp", service_id: "svc:ip:203.0.113.20:22/tcp", service: "ssh"},
  {id: "port:ip:203.0.113.20:8443/tcp", ip_id: "ip:203.0.113.20", number: 8443, protocol: "tcp", service_id: "svc:ip:203.0.113.20:8443/tcp", service: "tomcat"},
  {id: "port:ip:198.51.100.15:443/tcp", ip_id: "ip:198.51.100.15", number: 443, protocol: "tcp", service_id: "svc:ip:198.51.100.15:443/tcp", service: "nginx"},
  {id: "port:ip:198.51.100.15:8080/tcp", ip_id: "ip:198.51.100.15", number: 8080, protocol: "tcp", service_id: "svc:ip:198.51.100.15:8080/tcp", service: "node-api"},
  {id: "port:ip:192.0.2.50:8080/tcp", ip_id: "ip:192.0.2.50", number: 8080, protocol: "tcp", service_id: "svc:ip:192.0.2.50:8080/tcp", service: "edge-status"},
  {id: "port:ip:192.0.2.50:9000/tcp", ip_id: "ip:192.0.2.50", number: 9000, protocol: "tcp", service_id: "svc:ip:192.0.2.50:9000/tcp", service: "prometheus"}
] AS row
MATCH (ip:IP {id: row.ip_id})
MERGE (p:Port {id: row.id})
SET p.number = row.number,
    p.protocol = row.protocol,
    p.status = "open",
    p.sources = ["naabu", "nmap", "demo-seed"],
    p.created_at = coalesce(p.created_at, now),
    p.first_seen_at = coalesce(p.first_seen_at, now),
    p.last_seen_at = now,
    p.demo = true
MERGE (ip)-[:HAS_PORT]->(p)
MERGE (svc:Service {id: row.service_id})
SET svc.name = row.service,
    svc.sources = ["nmap", "demo-seed"],
    svc.created_at = coalesce(svc.created_at, now),
    svc.last_seen_at = now,
    svc.demo = true
MERGE (p)-[:HAS_SERVICE]->(svc)
MERGE (p)-[:RUNS]->(svc);

WITH "2026-06-10T22:45:00Z" AS now
UNWIND [
  {
    id: "ep:GET:https://www.demo-corp.test/",
    port_id: "port:ip:203.0.113.10:443/tcp",
    url: "https://www.demo-corp.test/",
    status_code: 200,
    title: "Demo Corp Home",
    tech: ["nginx", "Next.js"],
    crawl_status: "success",
    content_length: 48231,
    headers: ["Server: nginx", "X-Powered-By: Next.js"],
    changed_at: "2026-06-10T22:30:00Z",
    changed_fields: ["title", "body_hash"]
  },
  {
    id: "ep:GET:http://www.demo-corp.test/",
    port_id: "port:ip:203.0.113.10:80/tcp",
    url: "http://www.demo-corp.test/",
    status_code: 301,
    title: "Redirect to HTTPS",
    tech: ["nginx"],
    crawl_status: "success",
    content_length: 178,
    headers: ["Location: https://www.demo-corp.test/"],
    changed_at: null,
    changed_fields: []
  },
  {
    id: "ep:GET:https://api.demo-corp.test/v1/users",
    port_id: "port:ip:203.0.113.10:443/tcp",
    url: "https://api.demo-corp.test/v1/users",
    status_code: 200,
    title: "Demo API - Users",
    tech: ["FastAPI", "Uvicorn"],
    crawl_status: "success",
    content_length: 12890,
    headers: ["Content-Type: application/json", "Access-Control-Allow-Origin: *"],
    changed_at: null,
    changed_fields: []
  },
  {
    id: "ep:GET:https://admin.demo-corp.test:8443/login",
    port_id: "port:ip:203.0.113.20:8443/tcp",
    url: "https://admin.demo-corp.test:8443/login",
    status_code: 200,
    title: "Admin Login",
    tech: ["Tomcat", "Spring Boot"],
    crawl_status: "auth_required",
    content_length: 26511,
    headers: ["Server: Apache-Coyote"],
    changed_at: "2026-06-10T22:35:00Z",
    changed_fields: ["status_code"]
  },
  {
    id: "ep:GET:https://pay.demo-payments.test/checkout",
    port_id: "port:ip:198.51.100.15:443/tcp",
    url: "https://pay.demo-payments.test/checkout",
    status_code: 200,
    title: "Payment Checkout",
    tech: ["React", "nginx"],
    crawl_status: "success",
    content_length: 73420,
    headers: ["Server: nginx"],
    changed_at: null,
    changed_fields: []
  },
  {
    id: "ep:GET:http://pay.demo-payments.test:8080/debug",
    port_id: "port:ip:198.51.100.15:8080/tcp",
    url: "http://pay.demo-payments.test:8080/debug",
    status_code: 500,
    title: "Debug Console",
    tech: ["Express", "Node.js"],
    crawl_status: "error",
    content_length: 5300,
    headers: ["X-Debug-Mode: true"],
    changed_at: "2026-06-10T22:40:00Z",
    changed_fields: ["status_code", "title"]
  },
  {
    id: "ep:GET:https://auth.demo-payments.test/oauth/authorize",
    port_id: "port:ip:198.51.100.15:443/tcp",
    url: "https://auth.demo-payments.test/oauth/authorize",
    status_code: 302,
    title: "OAuth Authorize",
    tech: ["Keycloak", "Java"],
    crawl_status: "success",
    content_length: 0,
    headers: ["Location: /login"],
    changed_at: null,
    changed_fields: []
  },
  {
    id: "ep:GET:http://192.0.2.50:8080/status",
    port_id: "port:ip:192.0.2.50:8080/tcp",
    url: "http://192.0.2.50:8080/status",
    status_code: 200,
    title: "Edge Status",
    tech: ["Go", "net/http"],
    crawl_status: "success",
    content_length: 920,
    headers: ["Content-Type: application/json"],
    changed_at: null,
    changed_fields: []
  },
  {
    id: "ep:GET:http://192.0.2.50:9000/metrics",
    port_id: "port:ip:192.0.2.50:9000/tcp",
    url: "http://192.0.2.50:9000/metrics",
    status_code: 401,
    title: "Metrics",
    tech: ["Prometheus"],
    crawl_status: "auth_required",
    content_length: 2380,
    headers: ["WWW-Authenticate: Basic"],
    changed_at: null,
    changed_fields: []
  }
] AS row
MATCH (p:Port {id: row.port_id})
MERGE (ep:HTTPEndpoint {id: row.id})
SET ep.url = row.url,
    ep.method = "GET",
    ep.status_code = row.status_code,
    ep.title = row.title,
    ep.body_hash = "demo-" + row.id,
    ep.content_length = row.content_length,
    ep.response_headers = row.headers,
    ep.ssl_cert_cn = "",
    ep.ssl_cert_issuer = "",
    ep.tech = row.tech,
    ep.crawl_status = row.crawl_status,
    ep.sources = ["httpx", "katana", "demo-seed"],
    ep.url_fragment = "",
    ep.created_at = coalesce(ep.created_at, now),
    ep.first_seen_at = coalesce(ep.first_seen_at, now),
    ep.last_seen_at = now,
    ep.changed_at = row.changed_at,
    ep.changed_fields = row.changed_fields,
    ep.demo = true
MERGE (p)-[:EXPOSES]->(ep);

WITH "2026-06-10T22:45:00Z" AS now
UNWIND [
  {id: "dir:demo:www-login", ep_id: "ep:GET:https://www.demo-corp.test/", path: "/login", method: "GET", status_code: 200, content_type: "text/html", size: 8320},
  {id: "dir:demo:www-static", ep_id: "ep:GET:https://www.demo-corp.test/", path: "/static/", method: "GET", status_code: 403, content_type: "text/html", size: 512},
  {id: "dir:demo:api-swagger", ep_id: "ep:GET:https://api.demo-corp.test/v1/users", path: "/swagger-ui/", method: "GET", status_code: 200, content_type: "text/html", size: 18400},
  {id: "dir:demo:api-admin", ep_id: "ep:GET:https://api.demo-corp.test/v1/users", path: "/v1/admin", method: "GET", status_code: 401, content_type: "application/json", size: 180},
  {id: "dir:demo:admin-api-config", ep_id: "ep:GET:https://admin.demo-corp.test:8443/login", path: "/api/config", method: "GET", status_code: 200, content_type: "application/json", size: 1240},
  {id: "dir:demo:admin-backup", ep_id: "ep:GET:https://admin.demo-corp.test:8443/login", path: "/backup.zip", method: "GET", status_code: 403, content_type: "application/zip", size: 0},
  {id: "dir:demo:pay-assets", ep_id: "ep:GET:https://pay.demo-payments.test/checkout", path: "/assets/", method: "GET", status_code: 200, content_type: "text/html", size: 2048},
  {id: "dir:demo:pay-env", ep_id: "ep:GET:https://pay.demo-payments.test/checkout", path: "/.env", method: "GET", status_code: 403, content_type: "text/plain", size: 64},
  {id: "dir:demo:debug-vars", ep_id: "ep:GET:http://pay.demo-payments.test:8080/debug", path: "/debug/vars", method: "GET", status_code: 200, content_type: "application/json", size: 4096},
  {id: "dir:demo:debug-internal", ep_id: "ep:GET:http://pay.demo-payments.test:8080/debug", path: "/api/internal", method: "GET", status_code: 500, content_type: "application/json", size: 900}
] AS row
MATCH (ep:HTTPEndpoint {id: row.ep_id})
MERGE (d:DirEntry {id: row.id})
SET d.endpoint_id = row.ep_id,
    d.path = row.path,
    d.method = row.method,
    d.status_code = row.status_code,
    d.content_type = row.content_type,
    d.size = row.size,
    d.sources = ["ffuf", "gobuster", "demo-seed"],
    d.created_at = coalesce(d.created_at, now),
    d.last_seen_at = now,
    d.demo = true
MERGE (ep)-[:EXPOSES_PATH]->(d);

WITH "2026-06-10T22:45:00Z" AS now
UNWIND [
  {
    id: "file:demo:www-app-js",
    ep_id: "ep:GET:https://www.demo-corp.test/",
    url: "https://www.demo-corp.test/static/app.4f2a.js",
    content_type: "application/javascript",
    size: 188240,
    content_hash: "sha256:demo-www-app-4f2a",
    local_path: "outs/demo/www/app.4f2a.js"
  },
  {
    id: "file:demo:api-swagger-js",
    ep_id: "ep:GET:https://api.demo-corp.test/v1/users",
    url: "https://api.demo-corp.test/swagger-ui/swagger-ui-bundle.js",
    content_type: "application/javascript",
    size: 322110,
    content_hash: "sha256:demo-api-swagger",
    local_path: "outs/demo/api/swagger-ui-bundle.js"
  },
  {
    id: "file:demo:admin-js",
    ep_id: "ep:GET:https://admin.demo-corp.test:8443/login",
    url: "https://admin.demo-corp.test:8443/static/admin.js",
    content_type: "application/javascript",
    size: 88420,
    content_hash: "sha256:demo-admin-js",
    local_path: "outs/demo/admin/admin.js"
  },
  {
    id: "file:demo:pay-checkout-js",
    ep_id: "ep:GET:https://pay.demo-payments.test/checkout",
    url: "https://pay.demo-payments.test/assets/checkout.91ab.js",
    content_type: "application/javascript",
    size: 146900,
    content_hash: "sha256:demo-pay-checkout",
    local_path: "outs/demo/payments/checkout.91ab.js"
  },
  {
    id: "file:demo:edge-client-js",
    ep_id: "ep:GET:http://192.0.2.50:8080/status",
    url: "http://192.0.2.50:8080/static/client.js",
    content_type: "application/javascript",
    size: 12600,
    content_hash: "sha256:demo-edge-client",
    local_path: "outs/demo/edge/client.js"
  }
] AS row
MATCH (ep:HTTPEndpoint {id: row.ep_id})
MERGE (f:File {id: row.id})
SET f.url = row.url,
    f.content_type = row.content_type,
    f.size = row.size,
    f.content_hash = row.content_hash,
    f.local_path = row.local_path,
    f.sources = ["katana", "demo-seed"],
    f.created_at = coalesce(f.created_at, now),
    f.last_seen_at = now,
    f.demo = true
MERGE (ep)-[:REFERENCES]->(f);

WITH "2026-06-10T22:45:00Z" AS now
UNWIND [
  {id: "secret:demo:admin-jwt", file_id: "file:demo:admin-js", type: "JWTSecret", preview: "jwt_secret=demo_***", line: 42},
  {id: "secret:demo:pay-stripe", file_id: "file:demo:pay-checkout-js", type: "StripeSecretKey", preview: "sk_test_demo_***", line: 128},
  {id: "secret:demo:api-token", file_id: "file:demo:api-swagger-js", type: "InternalAPIToken", preview: "demo-token-***", line: 311}
] AS row
MATCH (f:File {id: row.file_id})
MERGE (s:Secret {id: row.id})
SET s.type = row.type,
    s.value_preview = row.preview,
    s.line = row.line,
    s.created_at = coalesce(s.created_at, now),
    s.last_seen_at = now,
    s.demo = true
MERGE (f)-[:MAY_CONTAIN]->(s);

WITH "2026-06-10T22:45:00Z" AS now
UNWIND [
  {
    id: "vuln:demo:debug-console",
    ep_id: "ep:GET:http://pay.demo-payments.test:8080/debug",
    type: "exposed-debug-console",
    title: "Debug console exposed",
    severity: "critical",
    detail: "Demo debug endpoint is reachable without authentication and exposes stack traces.",
    evidence: "GET /debug returned X-Debug-Mode: true with stack trace marker"
  },
  {
    id: "vuln:demo:admin-panel",
    ep_id: "ep:GET:https://admin.demo-corp.test:8443/login",
    type: "exposed-panel",
    title: "Exposed admin login panel",
    severity: "high",
    detail: "Internet-facing admin panel discovered on non-standard TLS port.",
    evidence: "matched-at: https://admin.demo-corp.test:8443/login"
  },
  {
    id: "vuln:demo:cors-wildcard",
    ep_id: "ep:GET:https://api.demo-corp.test/v1/users",
    type: "misconfiguration",
    title: "Wildcard CORS on user API",
    severity: "medium",
    detail: "The user API returns Access-Control-Allow-Origin: * in demo data.",
    evidence: "Access-Control-Allow-Origin: *"
  },
  {
    id: "vuln:demo:missing-security-headers",
    ep_id: "ep:GET:https://www.demo-corp.test/",
    type: "missing-header",
    title: "Missing security headers",
    severity: "low",
    detail: "Strict-Transport-Security and Content-Security-Policy are absent in demo response.",
    evidence: "missing: strict-transport-security, content-security-policy"
  }
] AS row
MATCH (ep:HTTPEndpoint {id: row.ep_id})
MERGE (v:Vulnerability {id: row.id})
SET v.type = row.type,
    v.title = row.title,
    v.severity = row.severity,
    v.detail = row.detail,
    v.evidence = row.evidence,
    v.sources = ["nuclei", "demo-seed"],
    v.created_at = coalesce(v.created_at, now),
    v.last_seen_at = now,
    v.demo = true
MERGE (ep)-[:MAY_BE_VULNERABLE_TO]->(v);

WITH "2026-06-10T22:45:00Z" AS now
UNWIND [
  {id: "scan:demo:www-httpx", ep_id: "ep:GET:https://www.demo-corp.test/", tool: "httpx", config: "-title -tech-detect -status-code", config_hash: "demo01", wordlist: "", findings_count: 1},
  {id: "scan:demo:www-katana", ep_id: "ep:GET:https://www.demo-corp.test/", tool: "katana", config: "-d 3 -js-crawl", config_hash: "demo02", wordlist: "", findings_count: 3},
  {id: "scan:demo:api-ffuf", ep_id: "ep:GET:https://api.demo-corp.test/v1/users", tool: "ffuf", config: "-w common-api.txt", config_hash: "demo03", wordlist: "common-api.txt", findings_count: 2},
  {id: "scan:demo:admin-nuclei", ep_id: "ep:GET:https://admin.demo-corp.test:8443/login", tool: "nuclei", config: "-severity high,critical", config_hash: "demo04", wordlist: "nuclei-templates", findings_count: 1},
  {id: "scan:demo:pay-debug-nuclei", ep_id: "ep:GET:http://pay.demo-payments.test:8080/debug", tool: "nuclei", config: "-tags exposure,debug", config_hash: "demo05", wordlist: "nuclei-templates", findings_count: 1},
  {id: "scan:demo:pay-ffuf", ep_id: "ep:GET:https://pay.demo-payments.test/checkout", tool: "gobuster", config: "-w raft-small-words.txt", config_hash: "demo06", wordlist: "raft-small-words.txt", findings_count: 2}
] AS row
MATCH (ep:HTTPEndpoint {id: row.ep_id})
MERGE (sr:ScanRun {id: row.id})
SET sr.tool = row.tool,
    sr.config = row.config,
    sr.config_hash = row.config_hash,
    sr.wordlist = row.wordlist,
    sr.findings_count = row.findings_count,
    sr.started_at = "2026-06-10T22:15:00Z",
    sr.finished_at = now,
    sr.last_run_at = now,
    sr.created_at = coalesce(sr.created_at, now),
    sr.demo = true
MERGE (sr)-[:RAN]->(ep);

MATCH (a:Asset {id: "test"})
OPTIONAL MATCH (a)-[:HAS_ROOT]->(r:RootDomain)
OPTIONAL MATCH (r)-[:HAS_SUB]->(s:Subdomain)
OPTIONAL MATCH (s)-[:RESOLVES_TO]->(ip_from_sub:IP)
OPTIONAL MATCH (a)-[:HAS_IP]->(ip_direct:IP)
WITH a, collect(DISTINCT r) AS roots, collect(DISTINCT s) AS subs,
     collect(DISTINCT ip_from_sub) + collect(DISTINCT ip_direct) AS raw_ips
UNWIND raw_ips AS ip
WITH a, roots, subs, collect(DISTINCT ip) AS ips
OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
OPTIONAL MATCH (p)-[:EXPOSES]->(ep:HTTPEndpoint)
OPTIONAL MATCH (ep)-[:MAY_BE_VULNERABLE_TO]->(v:Vulnerability)
RETURN a.id AS asset_id,
       size(roots) AS root_domains,
       size(subs) AS subdomains,
       size(ips) AS ips,
       count(DISTINCT p) AS ports,
       count(DISTINCT ep) AS endpoints,
       count(DISTINCT v) AS vulnerabilities;
