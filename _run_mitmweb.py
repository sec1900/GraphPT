from mitmproxy.tools.main import mitmweb
import sys
sys.exit(mitmweb([
    "-s", "graphpt/collector/mitm_addon.py",
    "--set", "graphpt_asset=mytarget",
    "--set", "web_password=graphpt",
    "-p", "8888",
    "--web-port", "8889",
    "--no-web-open-browser",
]))
