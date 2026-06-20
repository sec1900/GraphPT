"""清理指定资产的 ScanRun 节点，方便重新测试。用法: python tools/clean_scan.py [asset_id]"""
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv; load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))
from neo4j import GraphDatabase
d = GraphDatabase.driver(os.getenv("NEO4J_URI"), auth=(os.getenv("NEO4J_USER"), os.getenv("NEO4J_PASSWORD")))
aid = sys.argv[1] if len(sys.argv) > 1 else "mlws1900"
with d.session() as s:
    s.run(f"MATCH (sr:ScanRun) WHERE sr.asset_id='{aid}' DETACH DELETE sr")
    print(f"ScanRun cleaned for {aid}")
d.close()
