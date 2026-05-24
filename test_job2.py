import requests
import time
import json

job_id = 'dfb0e67fbdae4484b801fe2487e19515'

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
            print(f'  - {v.get("type")} at line {v.get("line")}')
        print(json.dumps(data, indent=2, ensure_ascii=False))
        break
    time.sleep(1)
