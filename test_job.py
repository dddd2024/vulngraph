import requests
import time
import json

job_id = '1443b6b0c83a4d309bd869aafba1e710'

# 等待任务完成
for i in range(10):
    response = requests.get(f'http://127.0.0.1:8000/jobs/{job_id}')
    data = response.json()
    status = data.get('status')
    print(f'Attempt {i+1}: status = {status}')
    if status in ('completed', 'failed'):
        print(json.dumps(data, indent=2, ensure_ascii=False))
        break
    time.sleep(1)
