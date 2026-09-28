"""
OmniUil AI v5.0 — Vendor Assessment (TPRM)
===========================================
Third Party Risk Management para criptografia PQC.
Permite que bancos e empresas avaliem fornecedores terceiros
via formulário estruturado ou API — sem precisar de acesso
ao código-fonte do fornecedor.

Alinhado com:
- EO-14412 (junho/2026) — supply chain PQC requirements
- NIST SP 800-161 — C-SCRM
- ECB ICT Risk Framework — third party risk
- BACEN Resolução 4.658 — risco de terceiros
"""
from __future__ import annotations
import json, uuid, hashlib
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from flask import Flask, request, jsonify

# ── Questionário CNSA 2.0 para fornecedores ──────────────────────────────────
ASSESSMENT_QUESTIONS = [
    {
        "id": "Q001",
        "category": "inventory",
        "question": "Sua organização possui inventário de algoritmos criptográficos (CBOM)?",
        "options": ["Sim, completo e atualizado","Sim, parcial","Em desenvolvimento","Não"],
        "weight": 10,
        "cnsa2_relevant": True,
    },
    {
        "id": "Q002",
        "category": "algorithms",
        "question": "Sua infraestrutura usa RSA para criptografia ou assinaturas digitais?",
        "options": ["Não usa RSA","RSA em sistemas não-críticos apenas","RSA em sistemas críticos","RSA amplamente usado"],
        "weight": 15,
        "cnsa2_relevant": True,
    },
    {
        "id": "Q003",
        "category": "algorithms",
        "question": "Sua infraestrutura usa ECDSA/ECDH para criptografia ou assinaturas?",
        "options": ["Não usa ECDSA","ECDSA em sistemas não-críticos","ECDSA em sistemas críticos","ECDSA amplamente usado"],
        "weight": 12,
        "cnsa2_relevant": True,
    },
    {
        "id": "Q004",
        "category": "migration",
        "question": "Sua organização possui roadmap formal de migração PQC?",
        "options": ["Sim, aprovado e em execução","Sim, em aprovação","Em elaboração","Não possui"],
        "weight": 15,
        "cnsa2_relevant": True,
    },
    {
        "id": "Q005",
        "category": "migration",
        "question": "Qual é o prazo estimado para migração completa para algoritmos CNSA 2.0?",
        "options": ["Antes de jan/2027","2027-2028","2029-2030","Não definido"],
        "weight": 10,
        "cnsa2_relevant": True,
    },
    {
        "id": "Q006",
        "category": "tools",
        "question": "Sua organização usa ferramentas automatizadas para detectar uso de algoritmos vulneráveis no código?",
        "options": ["Sim, com cobertura completa","Sim, cobertura parcial","Manual apenas","Não usa"],
        "weight": 10,
        "cnsa2_relevant": False,
    },
    {
        "id": "Q007",
        "category": "hybrid",
        "question": "Sua organização implementa ou planeja modo híbrido (clássico + PQC) durante a transição?",
        "options": ["Já implementado","Planejado para 2025-2026","Em avaliação","Não considera"],
        "weight": 8,
        "cnsa2_relevant": True,
    },
    {
        "id": "Q008",
        "category": "tls",
        "question": "Todos os serviços externos usam TLS 1.3 como versão mínima?",
        "options": ["Sim, todos","Maioria (>80%)","Parcial (<80%)","TLS 1.0/1.1 ainda em uso"],
        "weight": 8,
        "cnsa2_relevant": True,
    },
    {
        "id": "Q009",
        "category": "secrets",
        "question": "Segredos e chaves criptográficas são gerenciados por cofre (Vault, KMS)?",
        "options": ["Sim, 100% via cofre","Maioria via cofre","Parcialmente","Hardcoded ou arquivos"],
        "weight": 12,
        "cnsa2_relevant": False,
    },
    {
        "id": "Q010",
        "category": "certification",
        "question": "Seus sistemas possuem certificação relevante de segurança?",
        "options": ["FIPS 140-3 validado","ISO 27001 + SOC 2","ISO 27001 apenas","Nenhuma certificação"],
        "weight": 10,
        "cnsa2_relevant": False,
    },
]

# Pontuação por resposta (índice 0=melhor, 3=pior)
RESPONSE_SCORES = [100, 66, 33, 0]

@dataclass
class VendorAssessment:
    """Avaliação PQC de um fornecedor terceiro."""
    assessment_id:    str
    vendor_name:      str
    vendor_email:     str
    assessor_company: str
    responses:        dict[str, int]  # Q001 → índice da resposta
    score:            int
    risk_level:       str
    risk_color:       str
    cnsa2_score:      int
    gaps:             list[str]
    recommendations:  list[str]
    compliant:        bool
    generated_at:     str
    expires_at:       str

def calculate_vendor_score(responses: dict[str, int]) -> dict:
    """Calcula score PQC do fornecedor baseado nas respostas."""
    total_weight  = sum(q["weight"] for q in ASSESSMENT_QUESTIONS)
    earned_points = 0
    cnsa2_weight  = 0
    cnsa2_earned  = 0
    gaps          = []
    recommendations = []

    for q in ASSESSMENT_QUESTIONS:
        qid      = q["id"]
        response = responses.get(qid, 3)  # default: pior resposta
        score    = RESPONSE_SCORES[min(response, 3)]
        weighted = (score / 100) * q["weight"]
        earned_points += weighted

        if q["cnsa2_relevant"]:
            cnsa2_weight += q["weight"]
            cnsa2_earned += weighted

        # Identifica gaps
        if score < 66:
            gaps.append(f"{q['category'].upper()}: {q['question'][:60]}...")
        if score == 0:
            recommendations.append(_get_recommendation(qid))

    total_score  = int((earned_points / total_weight) * 100)
    cnsa2_score  = int((cnsa2_earned / cnsa2_weight) * 100) if cnsa2_weight > 0 else 0

    if total_score >= 80:
        risk_level, risk_color = "LOW", "green"
    elif total_score >= 60:
        risk_level, risk_color = "MEDIUM", "yellow"
    elif total_score >= 40:
        risk_level, risk_color = "HIGH", "orange"
    else:
        risk_level, risk_color = "CRITICAL", "red"

    compliant = total_score >= 70 and cnsa2_score >= 60

    return {
        "score":          total_score,
        "cnsa2_score":    cnsa2_score,
        "risk_level":     risk_level,
        "risk_color":     risk_color,
        "gaps":           gaps[:5],
        "recommendations":recommendations[:3],
        "compliant":      compliant,
    }

def _get_recommendation(qid: str) -> str:
    recs = {
        "Q001": "Implementar CBOM usando OmniUil AI --format cbom",
        "Q002": "Iniciar migração RSA → ML-KEM-768 imediatamente (CNSA 2.0 jan/2027)",
        "Q003": "Migrar ECDSA → ML-DSA-65 (NIST FIPS 204)",
        "Q004": "Elaborar roadmap PQC formal com aprovação C-level",
        "Q005": "Definir deadline interno antes de jan/2027 (CNSA 2.0)",
        "Q006": "Implementar scanner PQC automatizado no pipeline CI/CD",
        "Q007": "Adotar modo híbrido X25519+ML-KEM-768 como passo intermediário",
        "Q008": "Desabilitar TLS 1.0/1.1, configurar TLS 1.3 como mínimo",
        "Q009": "Migrar segredos para HashiCorp Vault ou AWS KMS",
        "Q010": "Iniciar processo de certificação FIPS 140-3 ou ISO 27001",
    }
    return recs.get(qid, "Revisar e remediar conforme NIST SP 800-131A")

def create_assessment(
    vendor_name:      str,
    vendor_email:     str,
    assessor_company: str,
    responses:        dict[str, int],
) -> VendorAssessment:
    """Cria avaliação completa de fornecedor."""
    result      = calculate_vendor_score(responses)
    now         = datetime.now(timezone.utc)
    expires     = now.replace(year=now.year + 1)
    assessment_id = f"VA-{hashlib.sha256(f'{vendor_name}{now.isoformat()}'.encode()).hexdigest()[:8].upper()}"

    return VendorAssessment(
        assessment_id=    assessment_id,
        vendor_name=      vendor_name,
        vendor_email=     vendor_email,
        assessor_company= assessor_company,
        responses=        responses,
        score=            result["score"],
        risk_level=       result["risk_level"],
        risk_color=       result["risk_color"],
        cnsa2_score=      result["cnsa2_score"],
        gaps=             result["gaps"],
        recommendations=  result["recommendations"],
        compliant=        result["compliant"],
        generated_at=     now.isoformat(),
        expires_at=       expires.isoformat(),
    )

def assessment_to_report(a: VendorAssessment) -> str:
    """Gera relatório HTML do assessment."""
    risk_colors = {
        "LOW":"#00e676","MEDIUM":"#ffff00",
        "HIGH":"#ffaa00","CRITICAL":"#ff4444"
    }
    color = risk_colors.get(a.risk_level,"#8888ff")
    gaps_html = "".join(f"<li>{g}</li>" for g in a.gaps)
    recs_html = "".join(f"<li>{r}</li>" for r in a.recommendations)

    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8">
<title>Vendor PQC Assessment — {a.vendor_name}</title>
<style>
body{{font-family:'Segoe UI',system-ui;background:#020b14;color:#e0f0ff;padding:2rem;margin:0}}
h1{{color:#00d4ff}}h2{{color:#4a9abb;border-bottom:1px solid #1a3a5c;padding-bottom:.5rem}}
.score{{font-size:3rem;font-weight:700;color:{color}}}
.card{{background:#07111e;border:1px solid #1a3a5c;border-radius:8px;padding:1.5rem;margin:1rem 0}}
.badge{{display:inline-block;padding:4px 12px;border-radius:20px;font-weight:700;
        background:{color}22;color:{color};border:1px solid {color}44}}
table{{width:100%;border-collapse:collapse}}
th{{background:#0a1628;padding:.6rem;text-align:left;color:#4a9abb;font-size:.75rem}}
td{{padding:.6rem;border-bottom:1px solid #0a1628;font-size:.85rem}}
ul{{line-height:2;color:#8aaa}}
.footer{{color:#4a6a8a;font-size:.75rem;margin-top:2rem;border-top:1px solid #1a3a5c;padding-top:1rem}}
</style></head><body>
<h1>⚡ OmniUil AI — Vendor PQC Assessment</h1>
<div class="card">
  <p>Fornecedor: <strong>{a.vendor_name}</strong> | Avaliador: {a.assessor_company}</p>
  <p>ID: <code>{a.assessment_id}</code> | Gerado: {a.generated_at[:10]} | Válido até: {a.expires_at[:10]}</p>
  <div class="score">{a.score}/100</div>
  <span class="badge">{a.risk_level} RISK</span>
  <span style="margin-left:1rem">CNSA 2.0 Score: <strong>{a.cnsa2_score}/100</strong></span>
  <span style="margin-left:1rem">Compliant: <strong style="color:{'#00e676' if a.compliant else '#ff4444'}">{'✅ SIM' if a.compliant else '❌ NÃO'}</strong></span>
</div>
<h2>Gaps Identificados</h2>
<div class="card"><ul>{gaps_html or '<li>Nenhum gap crítico identificado</li>'}</ul></div>
<h2>Recomendações Prioritárias</h2>
<div class="card"><ul>{recs_html or '<li>Manter práticas atuais e monitorar updates NIST</li>'}</ul></div>
<div class="footer">
OmniUil AI v5.0 — github.com/Uilcol/omniuil-ai<br>
Alinhado com EO-14412 (jun/2026), NIST FIPS 203/204/205, NSA CNSA 2.0, BACEN 4.658
</div></body></html>"""

# ── Endpoints Flask para integração com server.py ─────────────────────────────
def register_vendor_routes(app: Flask, API_VERSION: str):
    """Registra rotas de vendor assessment no servidor Flask existente."""

    @app.route(f"/api/{API_VERSION}/vendor/questions")
    def vendor_questions():
        """Retorna questionário de assessment."""
        return jsonify({
            "version": "1.0",
            "questions": ASSESSMENT_QUESTIONS,
            "instructions": (
                "Responda cada questão com o índice da opção (0=melhor, 3=pior). "
                "Score >= 70 e CNSA2 score >= 60 indica conformidade básica."
            ),
        })

    @app.route(f"/api/{API_VERSION}/vendor/assess", methods=["POST"])
    def vendor_assess():
        """Executa avaliação PQC de fornecedor."""
        body = request.get_json(force=True, silent=True) or {}
        vendor_name      = body.get("vendor_name","")
        vendor_email     = body.get("vendor_email","")
        assessor_company = body.get("assessor_company","")
        responses        = body.get("responses",{})

        if not vendor_name:
            return jsonify({"error":"vendor_name obrigatório"}), 400

        a = create_assessment(vendor_name, vendor_email, assessor_company, responses)
        return jsonify({
            "assessment_id":    a.assessment_id,
            "vendor_name":      a.vendor_name,
            "score":            a.score,
            "cnsa2_score":      a.cnsa2_score,
            "risk_level":       a.risk_level,
            "risk_color":       a.risk_color,
            "compliant":        a.compliant,
            "gaps":             a.gaps,
            "recommendations":  a.recommendations,
            "generated_at":     a.generated_at,
            "expires_at":       a.expires_at,
            "report_url":       f"/api/{API_VERSION}/vendor/report/{a.assessment_id}",
        })

    @app.route(f"/api/{API_VERSION}/vendor/report/<assessment_id>")
    def vendor_report(assessment_id: str):
        """Gera relatório HTML de um assessment (exemplo com dados mockados)."""
        # Em produção: buscar do SQLite pelo assessment_id
        mock = create_assessment(
            "Fornecedor Exemplo", "vendor@exemplo.com", "Sua Empresa",
            {"Q001":1,"Q002":2,"Q003":1,"Q004":0,"Q005":1,
             "Q006":1,"Q007":2,"Q008":0,"Q009":1,"Q010":2}
        )
        return assessment_to_report(mock), 200, {"Content-Type":"text/html; charset=utf-8"}
