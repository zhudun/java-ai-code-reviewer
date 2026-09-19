from java_reviewer.analyze.source import parse_java


SOURCE = """
package demo;

import java.util.Optional;

@Service
public class Demo {
    private HashMap<String, String> cache = new HashMap<>();

    @Transactional
    public String name(Optional<User> user) {
        return user.get().getName();
    }

    private void hidden() {
        // comment
    }
}
"""


def test_parse_class_and_method():
    unit = parse_java("Demo.java", SOURCE)
    assert unit.package == "demo"
    assert unit.classes[0].name == "Demo"
    assert unit.classes[0].has_annotation("Service")
    names = {method.name for method in unit.classes[0].methods}
    assert "name" in names
    assert "hidden" in names
    field = unit.classes[0].fields[0]
    assert field.name == "cache"
    tx = next(m for m in unit.classes[0].methods if m.name == "name")
    assert tx.has_annotation("Transactional")
    assert tx.is_public


def test_strip_keeps_line_numbers():
    src = "class A {\n  // hide\n  int x;\n}\n"
    unit = parse_java("A.java", src)
    assert "int x" in unit.clean
    assert unit.classes[0].fields[0].name == "x"
