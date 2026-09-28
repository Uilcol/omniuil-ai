"""Testes do invariante: narrativa SEMPRE coerente com risk_level.

Cobre o bug original: score=85 + RSA-CRITICAL retornava
"postura sólida" (texto derivado do score) em vez de
"Risco Alto" (texto derivado do nível final).
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from quantum_posture import calculate_quantum_posture


def _finding(rule_id, severity, title, file="x.py", line=1):
    return {"rule_id": rule_id, "severity": severity, "title": title,
            "file": file, "line": line}


# Um nível pode ter mais de uma narrativa válida — desde que todas sejam
# coerentes com o nível. Mapeamento nível → lista de prefixos aceitáveis.
PREFIXOS_VALIDOS = {
    "CRITICAL": ["Risco CRÍTICO"],
    "HIGH":     ["Risco Alto"],
    "MEDIUM":   ["Risco Médio"],
    "LOW":      ["Risco Baixo"],
    # MINIMAL tem 2 variantes válidas: com e sem findings
    "MINIMAL":  [
        "Postura criptográfica sólida",
        "Nenhuma vulnerabilidade criptográfica detectada",
    ],
}


def _verifica_coerencia(findings, label):
    r = calculate_quantum_posture(findings, "/tmp", 50)
    rec = r.recommendation
    lvl = r.risk_level

    prefixos = PREFIXOS_VALIDOS[lvl]
    ok = any(rec.startswith(p) for p in prefixos)

    assert ok, (
        f"{label}: incoerência!\n"
        f"  risk_level     = {lvl}\n"
        f"  recommendation = {rec!r}\n"
        f"  prefixos aceitos = {prefixos}"
    )
    print(f"  ✓ {label}: [{lvl}] {rec[:75]}...")


def test_caso_do_bug_original():
    """Antes: score=85 + RSA-CRITICAL → 'postura sólida' (errado).
    Depois: → 'Risco Alto' (coerente com o nível)."""
    _verifica_coerencia([
        _finding("QSC-001", "CRITICAL", "RSA detectado"),
    ], "1 CRITICAL, score alto")


def test_critical_forca_texto_critico():
    _verifica_coerencia([
        _finding("QSC-001", "CRITICAL", "RSA 1"),
        _finding("QSC-001", "CRITICAL", "RSA 2"),
        _finding("QSC-001", "CRITICAL", "RSA 3"),
    ], "3 CRITICAL")


def test_sem_findings_postura_solida():
    """Caso MINIMAL com 0 findings — early return com texto próprio."""
    _verifica_coerencia([], "0 findings")


def test_dois_high_texto_baixo():
    """2 HIGH sem CRITICAL → score médio-alto → LOW."""
    _verifica_coerencia(
        [_finding("QSC-010", "HIGH", f"MD5 {i}") for i in range(2)],
        "2 HIGH",
    )


def test_quantificacao_de_achados():
    """critical_count deve aparecer na narrativa quando >= 3."""
    findings = [
        _finding("QSC-001", "CRITICAL", f"RSA {i}") for i in range(5)
    ]
    r = calculate_quantum_posture(findings, "/tmp", 50)
    assert "5 sistemas/componentes críticos" in r.recommendation, (
        f"Narrativa não quantifica: {r.recommendation!r}"
    )
    print(f"  ✓ quantificação: {r.recommendation[:80]}...")


if __name__ == "__main__":
    print("Testando coerência narrativa...\n")
    test_sem_findings_postura_solida()
    test_caso_do_bug_original()
    test_critical_forca_texto_critico()
    test_dois_high_texto_baixo()
    test_quantificacao_de_achados()
    print("\n✅ Todos os testes de coerência passaram.")
