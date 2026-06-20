import os; os.environ['GRAPHPT_TOOL_TIMEOUT'] = '120'
import uvicorn; uvicorn.run('graphpt.web.app:web_app', host='127.0.0.1', port=8080)
