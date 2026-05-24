import requests
import json

# 测试 Java SQL 注入代码
java_code = '''import java.sql.*;

public class TestSQL {
    public void queryUser(Connection conn, String userId) throws SQLException {
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE id=" + userId;
        ResultSet rs = stmt.executeQuery(sql);
    }
}'''

# 调用 API
response = requests.post('http://127.0.0.1:8000/analyze-input-async', json={
    'input_type': 'code',
    'ai_mode': 'rule',
    'code': java_code
})
print('Status:', response.status_code)
print('Response:', json.dumps(response.json(), indent=2, ensure_ascii=False))
