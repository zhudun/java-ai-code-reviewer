from pathlib import Path

from java_reviewer.config import ReviewConfig
from java_reviewer.rules.engine import RuleEngine


def analyze(tmp_path: Path, name: str, source: str):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return RuleEngine().analyze_file(path, ReviewConfig())


def test_npe_optional_get(tmp_path: Path):
    findings = analyze(
        tmp_path,
        "Npe.java",
        """
        class Npe {
          String run(java.util.Optional<String> optional) {
            return optional.get();
          }
        }
        """,
    )
    assert any(item.rule_id == "java.npe" for item in findings)


def test_resource_leak(tmp_path: Path):
    findings = analyze(
        tmp_path,
        "Io.java",
        """
        import java.io.FileInputStream;
        class Io {
          void read(String path) throws Exception {
            FileInputStream in = new FileInputStream(path);
            in.read();
          }
        }
        """,
    )
    assert any(item.rule_id == "java.resource-leak" for item in findings)


def test_try_with_resources_is_clean(tmp_path: Path):
    findings = analyze(
        tmp_path,
        "SafeIo.java",
        """
        import java.io.FileInputStream;
        class SafeIo {
          int read(String path) throws Exception {
            try (FileInputStream in = new FileInputStream(path)) {
              return in.read();
            }
          }
        }
        """,
    )
    assert not any(item.rule_id == "java.resource-leak" for item in findings)


def test_thread_safety_simpledateformat(tmp_path: Path):
    findings = analyze(
        tmp_path,
        "Dates.java",
        """
        import java.text.SimpleDateFormat;
        class Dates {
          private static final SimpleDateFormat FMT = new SimpleDateFormat("yyyy");
        }
        """,
    )
    assert any(item.rule_id == "java.thread-safety" for item in findings)


def test_transaction_on_private(tmp_path: Path):
    findings = analyze(
        tmp_path,
        "Tx.java",
        """
        import org.springframework.stereotype.Service;
        import org.springframework.transaction.annotation.Transactional;
        @Service
        class Tx {
          @Transactional
          private void save() { repo.save(1); }
        }
        """,
    )
    assert any(item.rule_id == "java.transaction" and item.severity.value == "CRITICAL" for item in findings)


def test_sql_injection_concat(tmp_path: Path):
    findings = analyze(
        tmp_path,
        "Sql.java",
        """
        class Sql {
          void q(java.sql.Statement st, String name) throws Exception {
            st.executeQuery("SELECT * FROM t WHERE n='" + name + "'");
          }
        }
        """,
    )
    assert any(item.rule_id == "java.sql-injection" for item in findings)


def test_mybatis_dollar(tmp_path: Path):
    path = tmp_path / "UserMapper.xml"
    path.write_text("<select>SELECT * FROM t WHERE a=${name}</select>\n", encoding="utf-8")
    findings = RuleEngine().analyze_file(path, ReviewConfig())
    assert any(item.rule_id == "java.sql-injection" for item in findings)
