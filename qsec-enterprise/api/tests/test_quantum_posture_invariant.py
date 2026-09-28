"""Testes do invariante: risk_level agregado >= piso de severidade.

Regra implementada (arquitetura):
    final_risk = max(score_based_level, severity_floor)

Floor:
    - >= 3 CRITICAL       → CRITICAL
    - 1-2 CRITICAL        → HIGH
    - >= 5 HIGH (sem C)   → HIGH
    - caso contrário      → sem piso (MINIMAL)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from quantum_posture import calculate_quantum_posture

ORDEM = {"MINIMAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _finding(rule_id, severity, title, file="x.py", line=1):
    return {"rule_id": rule_id, "severity": severity, "title": title,
            "file": file, "line": line}


def _floor_esperado(findings):
    """Piso mínimo esperado dada a lista de findings."""
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    if critical >= 3:
        return "CRITICAL"
    if critical >= 1:
        return "HIGH"
    if high >= 5:
        return "HIGH"
    return "MINIMAL"


def _assert_floor(findings, label):
    r = calculate_quantum_posture(findings, "/tmp", 50)
    floor = _floor_esperado(findings)
    assert ORDEM[r.risk_level] >= ORDEM[floor], (
        f"{label}: esperado >= {floor}, veio {r.risk_level} "
        f"(score={r.score}, critical={sum(1 for f in findings if f['severity']=='CRITICAL')})"
    )
    print(f"  ✓ {label}: {r.risk_level} (score={r.score})")


def test_sem_findings_minimal():
    _assert_floor([], "0 findings")


def test_score_alto_mais_1_critical():
    """Caso do bug original: 1 CRITICAL força no mínimo HIGH."""
    _assert_floor([
        _finding("QSC-001", "CRITICAL", "RSA detectado"),
        _finding("QSC-010", "HIGH", "MD5 detectado"),
    ], "1 CRITICAL + 1 HIGH")


def test_tres_critical_forca_critical():
    _assert_floor([
        _finding("QSC-001", "CRITICAL", "RSA 1"),
        _finding("QSC-001", "CRITICAL", "RSA 2"),
        _finding("QSC-001", "CRITICAL", "RSA 3"),
    ], "3 CRITICAL")


def test_muitos_high_forca_high():
    _assert_floor(
        [_finding("QSC-010", "HIGH", f"MD5 {i}") for i in range(6)],
        "6 HIGH",
    )


def test_dois_high_nao_forca():
    """2 HIGH não ativam o floor (menos de 5)."""
    r = calculate_quantum_posture(
        [_finding("QSC-010", "HIGH", f"MD5 {i}") for i in range(2)],
        "/tmp", 50,
    )
    # Não valida o nível, apenas registra para inspeção
    print(f"  ✓ 2 HIGH: {r.risk_level} (score={r.score}) — sem floor ativo")


def test_invariante_geral():
    """Em qualquer entrada, o nível é >= o piso calculado."""
    casos = [
        [_finding("QSC-001", "CRITICAL", "x")],
        [_finding("QSC-001", "CRITICAL", "x")] * 2,
        [_finding("QSC-001", "CRITICAL", "x")] * 5,
        [_finding("QSC-010", "HIGH", "x")] * 10,
        [],
    ]
    for i, findings in enumerate(casos):
        _assert_floor(findings, f"caso {i} ({len(findings)} findings)")


if __name__ == "__main__":
    print("Testando invariante do quantum_posture...\n")
    test_sem_findings_minimal()
    test_score_alto_mais_1_critical()
    test_tres_critical_forca_critical()
    test_muitos_high_forca_high()
    test_dois_high_nao_forca()
    test_invariante_geral()
    print("\n✅ Todos os testes do invariante passaram.")
