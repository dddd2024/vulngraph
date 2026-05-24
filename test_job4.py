import requests
import time
import json

job_id = '25a34093242a45cebb3c99749a8087d5'

# 等待任务完成
for i in range(10):
    response = requests.get(f'http://127.0.0.1:8000/jobs/{job_id}')
    data = response.json()
    status = data.get('status')
    print(f'Attempt {i+1}: status = {status}')
    if status in ('completed', 'failed'):
        result = data.get('result', {})
        vulns = result.get('vulnerabilities', [])
        print(f'Vulnerabilities found: {len(vulns)}')
        for v in vulns:
            print(f'  - {v.get("type")} at line {v.get("line")}, engine: {v.get("engine")}')
        if len(vulns) == 0:
            print('Full response:', json.dumps(data, indent=2, ensure_ascii=False)[:2000])
        break
    time.sleep(1)
