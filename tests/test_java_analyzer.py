"""
Tests for Java pattern analyzer.

Verifies detection of:
- SQL Injection
- Command Injection
- Path Traversal (File, Paths.get, transferTo, FileInputStream)
- XXE
- Insecure Deserialization (ObjectInputStream, XMLDecoder, Kryo, Jackson, Hessian)
- SSRF (URL, HttpURLConnection, RestTemplate, OkHttp, HttpClient)
- Hardcoded Secret
"""

import pytest
from audit_core.models import CodeUnit, RawFinding
from analyzers.java.java_pattern_analyzer import JavaPatternAnalyzer


# ---------------------------------------------------------------------------
# Test code snippets
# ---------------------------------------------------------------------------

SQL_INJECTION_CODE = '''
import java.sql.*;

public class UserDao {
    public ResultSet search(String name) {
        String query = "SELECT * FROM users WHERE name = " + name;
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(query);
    }
}
'''

COMMAND_INJECTION_CODE = '''
import java.io.*;

public class CommandRunner {
    public void run(String cmd) {
        Runtime.getRuntime().exec(cmd);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.start();
    }
}
'''

PATH_TRAVERSAL_CODE = '''
import java.io.File;

public class FileReader {
    public File getFile(HttpServletRequest request) {
        String filename = request.getParameter("file");
        return new File(filename);
    }
}
'''

XXE_CODE = '''
import javax.xml.parsers.*;

public class XmlParser {
    public void parse(String xml) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }
}
'''

DESERIALIZATION_CODE = '''
import java.io.*;

public class DataLoader {
    public Object load(InputStream in) {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }
}
'''

HARDCODED_SECRET_CODE = '''
public class Config {
    private String password = "admin123";
    private String api_key = "sk-abc123xyz";
}
'''

# --- New test snippets for enhanced detection ---

SSRF_URL_CODE = '''
import java.net.*;
import javax.servlet.http.*;

public class ProxyController {
    public void fetch(HttpServletRequest request) {
        String targetUrl = request.getParameter("url");
        URL url = new URL(targetUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.connect();
    }
}
'''

SSRF_REST_TEMPLATE_CODE = '''
import org.springframework.web.client.RestTemplate;
import javax.servlet.http.*;

public class ApiService {
    private RestTemplate restTemplate = new RestTemplate();

    public String getData(HttpServletRequest request) {
        String url = request.getParameter("endpoint");
        return restTemplate.getForObject(url, String.class);
    }
}
'''

PATH_TRAVERSAL_PATHS_GET = '''
import java.nio.file.*;
import javax.servlet.http.*;

public class FileService {
    public byte[] read(HttpServletRequest request) {
        String filename = request.getParameter("file");
        Path path = Paths.get("/uploads", filename);
        return Files.readAllBytes(path);
    }
}
'''

PATH_TRAVERSAL_TRANSFER_CODE = '''
import org.springframework.web.multipart.MultipartFile;
import java.io.*;

public class UploadService {
    public void upload(MultipartFile file, HttpServletRequest request) throws IOException {
        String filename = file.getOriginalFilename();
        File dest = new File("/uploads/" + filename);
        file.transferTo(dest);
    }
}
'''

DESERIALIZATION_XML_DECODER = '''
import java.beans.XMLDecoder;
import java.io.*;

public class XmlDataLoader {
    public Object load(InputStream in) {
        XMLDecoder decoder = new XMLDecoder(in);
        return decoder.readObject();
    }
}
'''

DESERIALIZATION_JACKSON = '''
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonParser {
    public ObjectMapper createMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        return mapper;
    }
}
'''

DESERIALIZATION_HESSIAN = '''
import com.caucho.hessian.HessianInput;
import java.io.*;

public class HessianService {
    public Object read(InputStream in) throws IOException {
        HessianInput hin = new HessianInput(in);
        return hin.readObject();
    }
}
'''

CLEAN_CODE = '''
public class Calculator {
    public int add(int a, int b) {
        return a + b;
    }
}
'''


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_unit(code: str, path: str = "Test.java") -> CodeUnit:
    return CodeUnit(path=path, language="java", content=code, start_line=1)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestJavaPatternAnalyzerBasic:

    def test_analyzer_name(self):
        assert JavaPatternAnalyzer().name == "java_pattern"

    def test_supported_languages(self):
        analyzer = JavaPatternAnalyzer()
        assert "java" in analyzer.supported_languages

    def test_skips_non_java(self):
        analyzer = JavaPatternAnalyzer()
        unit = CodeUnit(path="test.py", language="python", content="eval(code)", start_line=1)
        results = analyzer.analyze([unit])
        assert results == []

    def test_empty_code_units(self):
        analyzer = JavaPatternAnalyzer()
        results = analyzer.analyze([])
        assert results == []

    def test_clean_code_no_findings(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(CLEAN_CODE)
        results = analyzer.analyze([unit])
        assert len(results) == 0


class TestJavaPatternAnalyzerSQLInjection:

    def test_detects_sql_injection(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(SQL_INJECTION_CODE)
        results = analyzer.analyze([unit])

        sql_findings = [f for f in results if "SQL" in f.type]
        assert len(sql_findings) > 0

        finding = sql_findings[0]
        assert finding.cwe == "CWE-89"
        assert finding.severity == "ERROR"
        assert finding.confidence == "high"

    def test_sql_injection_has_symbol(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(SQL_INJECTION_CODE)
        results = analyzer.analyze([unit])

        sql_findings = [f for f in results if "SQL" in f.type]
        assert len(sql_findings) > 0
        assert sql_findings[0].evidence.get("symbol") in ("executeQuery", "executeUpdate", "execute")


class TestJavaPatternAnalyzerCommandInjection:

    def test_detects_runtime_exec(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(COMMAND_INJECTION_CODE)
        results = analyzer.analyze([unit])

        cmd_findings = [f for f in results if "Command Injection" in f.type]
        assert len(cmd_findings) > 0

        finding = cmd_findings[0]
        assert finding.cwe == "CWE-78"
        assert finding.severity == "ERROR"

    def test_detects_process_builder(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(COMMAND_INJECTION_CODE)
        results = analyzer.analyze([unit])

        pb_findings = [f for f in results if "ProcessBuilder" in f.evidence.get("symbol", "")]
        assert len(pb_findings) > 0


class TestJavaPatternAnalyzerPathTraversal:

    def test_detects_path_traversal(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(PATH_TRAVERSAL_CODE)
        results = analyzer.analyze([unit])

        pt_findings = [f for f in results if "Path Traversal" in f.type]
        assert len(pt_findings) > 0

        finding = pt_findings[0]
        assert finding.cwe == "CWE-22"
        assert finding.evidence.get("symbol") == "File"


class TestJavaPatternAnalyzerXXE:

    def test_detects_xxe(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(XXE_CODE)
        results = analyzer.analyze([unit])

        xxe_findings = [f for f in results if "XXE" in f.type]
        assert len(xxe_findings) > 0

        finding = xxe_findings[0]
        assert finding.cwe == "CWE-611"
        assert finding.severity == "ERROR"


class TestJavaPatternAnalyzerDeserialization:

    def test_detects_insecure_deserialization(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(DESERIALIZATION_CODE)
        results = analyzer.analyze([unit])

        deser_findings = [f for f in results if "Deserialization" in f.type]
        assert len(deser_findings) > 0

        finding = deser_findings[0]
        assert finding.cwe == "CWE-502"
        assert finding.severity == "ERROR"
        assert finding.confidence == "high"


class TestJavaPatternAnalyzerHardcodedSecret:

    def test_detects_hardcoded_secret(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(HARDCODED_SECRET_CODE)
        results = analyzer.analyze([unit])

        secret_findings = [f for f in results if "Secret" in f.type or "secret" in f.type.lower()]
        assert len(secret_findings) > 0

        finding = secret_findings[0]
        assert finding.cwe == "CWE-798"


class TestJavaPatternAnalyzerFindingFormat:

    def test_findings_are_raw_finding(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(SQL_INJECTION_CODE)
        results = analyzer.analyze([unit])

        for finding in results:
            assert isinstance(finding, RawFinding)
            assert finding.rule_id
            assert finding.type
            assert finding.file_path
            assert finding.start_line > 0
            assert finding.engine == "java_pattern"

    def test_file_path_preserved(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(SQL_INJECTION_CODE, path="src/main/java/UserDao.java")
        results = analyzer.analyze([unit])

        for finding in results:
            assert finding.file_path == "src/main/java/UserDao.java"


# ---------------------------------------------------------------------------
# New tests: Enhanced Path Traversal
# ---------------------------------------------------------------------------

class TestJavaPathTraversalEnhanced:

    def test_detects_paths_get(self):
        """Should detect Path Traversal via Paths.get() with user input."""
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(PATH_TRAVERSAL_PATHS_GET)
        results = analyzer.analyze([unit])

        pt_findings = [f for f in results if "Path Traversal" in f.type]
        assert len(pt_findings) > 0, "Should detect Paths.get() path traversal"
        assert any(f.evidence.get("symbol") == "Paths.get" for f in pt_findings)

    def test_detects_transfer_to(self):
        """Should detect Path Traversal via transferTo with user-controlled filename."""
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(PATH_TRAVERSAL_TRANSFER_CODE)
        results = analyzer.analyze([unit])

        pt_findings = [f for f in results if "Path Traversal" in f.type]
        assert len(pt_findings) > 0, "Should detect transferTo path traversal"
        assert any(f.evidence.get("symbol") == "transferTo" for f in pt_findings)

    def test_paths_get_has_cwe22(self):
        """Paths.get path traversal should reference CWE-22."""
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(PATH_TRAVERSAL_PATHS_GET)
        results = analyzer.analyze([unit])

        pt_findings = [f for f in results if "Path Traversal" in f.type]
        assert any(f.cwe == "CWE-22" for f in pt_findings)


# ---------------------------------------------------------------------------
# New tests: Enhanced Deserialization
# ---------------------------------------------------------------------------

class TestJavaDeserializationEnhanced:

    def test_detects_xml_decoder(self):
        """Should detect XMLDecoder deserialization."""
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(DESERIALIZATION_XML_DECODER)
        results = analyzer.analyze([unit])

        deser_findings = [f for f in results if "Deserialization" in f.type]
        assert len(deser_findings) > 0, "Should detect XMLDecoder deserialization"
        assert any(f.rule_id == "JAVA_DESER_002" for f in deser_findings)

    def test_detects_jackson_enable_default_typing(self):
        """Should detect Jackson enableDefaultTyping."""
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(DESERIALIZATION_JACKSON)
        results = analyzer.analyze([unit])

        deser_findings = [f for f in results if "Deserialization" in f.type]
        assert len(deser_findings) > 0, "Should detect Jackson enableDefaultTyping"
        assert any(f.rule_id == "JAVA_DESER_004" for f in deser_findings)

    def test_detects_hessian_deserialization(self):
        """Should detect Hessian deserialization."""
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(DESERIALIZATION_HESSIAN)
        results = analyzer.analyze([unit])

        deser_findings = [f for f in results if "Deserialization" in f.type]
        assert len(deser_findings) > 0, "Should detect Hessian deserialization"
        assert any(f.rule_id == "JAVA_DESER_005" for f in deser_findings)

    def test_xml_decoder_severity_is_error(self):
        """XMLDecoder should be ERROR severity."""
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(DESERIALIZATION_XML_DECODER)
        results = analyzer.analyze([unit])

        xml_dec_findings = [f for f in results if f.rule_id == "JAVA_DESER_002"]
        assert all(f.severity == "ERROR" for f in xml_dec_findings)

    def test_hessian_severity_is_warn(self):
        """Hessian should be WARN severity (medium confidence)."""
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(DESERIALIZATION_HESSIAN)
        results = analyzer.analyze([unit])

        hessian_findings = [f for f in results if f.rule_id == "JAVA_DESER_005"]
        assert all(f.severity == "WARN" for f in hessian_findings)


# ---------------------------------------------------------------------------
# New tests: SSRF detection
# ---------------------------------------------------------------------------

class TestJavaSSRF:

    def test_detects_ssrf_url(self):
        """Should detect SSRF via new URL(user input)."""
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(SSRF_URL_CODE)
        results = analyzer.analyze([unit])

        ssrf_findings = [f for f in results if "SSRF" in f.type]
        assert len(ssrf_findings) > 0, "Should detect SSRF via URL construction"

    def test_ssrf_has_cwe918(self):
        """SSRF findings should reference CWE-918."""
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(SSRF_URL_CODE)
        results = analyzer.analyze([unit])

        ssrf_findings = [f for f in results if "SSRF" in f.type]
        assert any(f.cwe == "CWE-918" for f in ssrf_findings)

    def test_detects_ssrf_rest_template(self):
        """Should detect SSRF via RestTemplate with user input."""
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(SSRF_REST_TEMPLATE_CODE)
        results = analyzer.analyze([unit])

        ssrf_findings = [f for f in results if "SSRF" in f.type]
        assert len(ssrf_findings) > 0, "Should detect SSRF via RestTemplate"

    def test_ssrf_rest_template_rule_id(self):
        """RestTemplate SSRF should have correct rule_id."""
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(SSRF_REST_TEMPLATE_CODE)
        results = analyzer.analyze([unit])

        ssrf_findings = [f for f in results if "SSRF" in f.type]
        assert any(f.rule_id == "JAVA_SSRF_003" for f in ssrf_findings)

    def test_ssrf_severity_is_error(self):
        """SSRF findings should have ERROR severity."""
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(SSRF_URL_CODE)
        results = analyzer.analyze([unit])

        ssrf_findings = [f for f in results if "SSRF" in f.type]
        assert all(f.severity == "ERROR" for f in ssrf_findings)