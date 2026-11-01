"""Regras de envio do dashboard.

- exige destinatário válido sempre que a ação tem destinatário;
- em e-mails de prospecção, bloqueia afirmações já identificadas como não verificadas
  e exige uma linha de descadastro;
- só considera o e-mail enviado quando o Gmail devolve o id da mensagem.
"""
import re

MAIL_TYPES = {"send_email", "contract_proposal", "demo_report"}

_ADDR = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+")

# Frases já identificadas como não verificadas. Isto não prova que o resto do texto é
# verdadeiro: a leitura humana continua obrigatória.
_UNVERIFIED = [
    ("Pix ligado a CNSA 2.0", r"(?is)pix.{0,200}cnsa|cnsa.{0,200}pix"),
    ("Lei 14.063", r"14\.063"),
    ("'BACEN exige'", r"(?is)bacen.{0,40}exig|exig.{0,60}bacen"),
    ("contagem de findings (437/443)",
     r"(?is)\b(437|443)\b.{0,40}(finding|vulnerabilid|critical|achado)|(finding|vulnerabilid|critical|achado).{0,40}\b(437|443)\b"),
    ("'N CRITICAL'", r"(?i)\b\d+\s+(findings\s+)?critical"),
    ("contrato exige PQC/CNSA", r"(?is)contrato.{0,80}(pqc|cnsa)|(pqc|cnsa).{0,80}contrato"),
    ("'obrigatório em 2027'", r"(?is)obrigat[óo]ri.{0,40}2027"),
]

_OPT_OUT = re.compile(r"(?i)remover|descadastr|unsubscribe|opt[- ]?out|n[ãa]o (deseja|quiser) receber|do not wish")


def _s(v):
    return "" if v is None else str(v)


def wants_mail(row):
    t = _s(row["action_type"])
    return bool(_s(row["to_email"]).strip()) or t in MAIL_TYPES or t.startswith("prospecting")


def problems(row, content):
    out = []
    t = _s(row["action_type"])
    to = _s(row["to_email"]).strip()
    subj = _s(row["subject"])
    if not (len(to) <= 254 and _ADDR.fullmatch(to)):
        out.append("destinatário ausente ou inválido")
    if "\n" in subj or "\r" in subj:
        out.append("assunto com quebra de linha")
    if not _s(content).strip():
        out.append("texto vazio")
    if t.startswith("prospecting"):
        for name, rx in _UNVERIFIED:
            if re.search(rx, content or ""):
                out.append("afirmação não verificada: " + name)
        if not _OPT_OUT.search(content or ""):
            out.append("falta a linha de descadastro (ex.: Se não quiser receber mais mensagens, responda REMOVER.)")
    return out


def approve_and_send(row, content, send_fn):
    """Retorna (ok, detalhe). Para e-mail, só devolve ok=True depois que o Gmail confirmar."""
    if not wants_mail(row):
        return True, "ação aprovada (não envolve e-mail)"
    probs = problems(row, content)
    if probs:
        return False, "Bloqueado: " + "; ".join(probs)
    to = _s(row["to_email"]).strip()
    try:
        res = send_fn(to, _s(row["subject"]), content)
    except Exception as e:
        return False, "Falha ao enviar (%s): %s" % (type(e).__name__, _s(e)[:200])
    if not res:
        return False, "O Gmail não confirmou o envio (resposta vazia)"
    msg_id = res if isinstance(res, str) else "sem id"
    try:
        from db import log_conversation
        log_conversation(to, "sent", _s(row["subject"]), content, _s(row["agent"]))
    except Exception as e:
        return True, "Enviado para %s (id %s), mas o registro local falhou (%s)" % (to, msg_id, type(e).__name__)
    return True, "Enviado para %s (id %s)" % (to, msg_id)
