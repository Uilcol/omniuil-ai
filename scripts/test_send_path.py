#!/usr/bin/env python3
"""Teste offline do caminho de envio do dashboard.

Usa uma COPIA temporária do banco e um Gmail falso: nada real é enviado e o banco real
não é alterado (linhas de teste que escapem são removidas pelo marcador _TESTE_ENVIO_)."""
import base64
import email
import os
import shutil
import sqlite3
import sys
import tempfile
from email.header import decode_header, make_header
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AG = ROOT / "agents"
os.chdir(AG)
sys.path.insert(0, str(AG))

import db
import gmail_client

TAG = "_TESTE_ENVIO_"
results = []


def check(name, ok, extra=""):
    results.append(bool(ok))
    tail = "" if extra == "" else " [" + str(extra) + "]"
    print("  " + ("✅ " if ok else "❌ ") + name + tail)


def is_open(s):
    return s not in ("approved", "rejected")


class _Exec:
    def execute(self):
        return {"id": "msg-teste-1", "threadId": "t1"}


class _Msgs:
    def __init__(self, box):
        self.box = box

    def send(self, userId, body):
        self.box.append(body)
        return _Exec()


class _Users:
    def __init__(self, box):
        self.box = box

    def messages(self):
        return _Msgs(self.box)


class FakeService:
    def __init__(self):
        self.box = []

    def users(self):
        return _Users(self.box)


def _no_net(*a, **k):
    raise RuntimeError("rede bloqueada no teste")


print("\n[send_email com Gmail falso]")
fake = FakeService()
gmail_client.get_gmail_service = lambda: fake
res = gmail_client.send_email("dest@exemplo.com", "Olá ação", "corpo do e-mail")
check("devolve o id da mensagem", res == "msg-teste-1", res)
raw = fake.box[0]["raw"] if fake.box else ""
msg = email.message_from_bytes(base64.urlsafe_b64decode(raw)) if raw else None
check("cabeçalhos To e Subject corretos",
      msg is not None and msg["To"] == "dest@exemplo.com"
      and str(make_header(decode_header(msg["Subject"]))) == "Olá ação")
gmail_client.get_gmail_service = _no_net

orig_get_conn = db.get_conn
tmpdir = tempfile.mkdtemp()
tmp_db = os.path.join(tmpdir, "copia.db")
_src = orig_get_conn()
_dst = sqlite3.connect(tmp_db)
_src.backup(_dst)
_dst.close()
_src.close()


def tconn():
    c = sqlite3.connect(tmp_db)
    c.row_factory = sqlite3.Row
    return c


db.get_conn = tconn


def cleanup():
    db.get_conn = orig_get_conn
    try:
        c = orig_get_conn()
        c.execute("DELETE FROM pending_actions WHERE agent = ?", (TAG,))
        c.execute("DELETE FROM conversations WHERE agent = ?", (TAG,))
        c.commit()
        c.close()
    except Exception as e:
        print("  aviso: limpeza do banco real:", type(e).__name__, str(e)[:80])
    shutil.rmtree(tmpdir, ignore_errors=True)


def mk(action_type, to, subject="Assunto", content="Texto"):
    aid = db.add_pending(agent=TAG, action_type=action_type, subject=subject,
                         to_email=to, content=content, context="")
    c = tconn()
    r = c.execute("SELECT id FROM pending_actions WHERE id = ? AND agent = ?", (aid, TAG)).fetchone()
    c.close()
    if r is None:
        raise SystemExit("add_pending gravou fora da cópia do banco; abortado (limpeza será feita)")
    return aid


def status(aid):
    c = tconn()
    r = c.execute("SELECT status FROM pending_actions WHERE id = ?", (aid,)).fetchone()
    c.close()
    return r["status"] if r else None


def n_sent():
    c = tconn()
    n = c.execute("SELECT COUNT(*) FROM conversations WHERE direction = 'sent' AND agent = ?", (TAG,)).fetchone()[0]
    c.close()
    return n


try:
    import dashboard

    check("dashboard tem send_email como nome global", hasattr(dashboard, "send_email"))
    calls = []
    mode = {"fail": False}

    def fake_send(to, subject, body, reply_to_id=None):
        if mode["fail"]:
            raise RuntimeError("gmail indisponível")
        calls.append((to, subject, body))
        return "fake-id-1"

    dashboard.send_email = fake_send
    app = dashboard.app
    app.config["TESTING"] = True
    client = app.test_client()
    HDR = {"Origin": "http://localhost:9090", "Sec-Fetch-Site": "same-origin"}

    def post(aid, action, content=""):
        return client.post("/edit/%d" % aid, data={"action": action, "content": content},
                           headers=HDR, base_url="http://localhost:9090")

    print("\n[aprovar e enviar]")
    a = mk("send_email", "cliente@exemplo.com")
    check("item novo nasce em aberto (nem aprovado nem rejeitado)", is_open(status(a)), status(a))
    post(a, "approve", "Texto editado no dashboard")
    check("aprovar envia uma vez, com o texto editado",
          len(calls) == 1 and calls[0][2] == "Texto editado no dashboard", len(calls))
    check("só então vira approved", status(a) == "approved", status(a))
    check("registra a conversa como sent", n_sent() == 1, n_sent())

    print("\n[falha do Gmail]")
    mode["fail"] = True
    b = mk("send_email", "cliente2@exemplo.com")
    before = len(calls)
    r = post(b, "approve", "Oi")
    check("devolve 422 e mostra o erro",
          r.status_code == 422 and "Falha ao enviar" in r.get_data(as_text=True), r.status_code)
    check("o item continua em aberto", is_open(status(b)), status(b))
    check("não grava conversa sent", n_sent() == 1, n_sent())
    mode["fail"] = False
    post(b, "approve", "Oi de novo")
    check("com o Gmail de volta, o mesmo item é enviado",
          len(calls) == before + 1 and status(b) == "approved")

    print("\n[prospecção: afirmações não verificadas e descadastro]")
    optout = " Se não quiser receber mais mensagens, responda REMOVER."
    c1 = mk("prospecting_email_v5", "ciso@exemplo.com.br")
    n0 = len(calls)
    r = post(c1, "approve", "Encontramos 437 findings CRITICAL no Spring Security." + optout)
    check("bloqueia '437 findings CRITICAL'",
          r.status_code == 422 and "afirmação não verificada" in r.get_data(as_text=True))
    r = post(c1, "approve", "O CNSA 2.0 é obrigatório para o Pix em 2027." + optout)
    check("bloqueia Pix ligado a CNSA 2.0", r.status_code == 422)
    r = post(c1, "approve", "Olá, gostaria de apresentar o OmniUil AI.")
    check("bloqueia e-mail sem linha de descadastro",
          r.status_code == 422 and "descadastro" in r.get_data(as_text=True))
    check("nada foi enviado nesses três casos", len(calls) == n0 and is_open(status(c1)))
    post(c1, "approve", "Olá, gostaria de apresentar o OmniUil AI." + optout)
    check("texto limpo com descadastro é enviado", len(calls) == n0 + 1 and status(c1) == "approved")

    print("\n[destinatário e tipos sem e-mail]")
    d = mk("send_email", "a@b.com\nBcc: outro@exemplo.com")
    n1 = len(calls)
    r = post(d, "approve", "Oi")
    check("destinatário com quebra de linha é bloqueado", r.status_code == 422 and len(calls) == n1)
    e = mk("send_email", "")
    r = post(e, "approve", "Oi")
    check("e-mail sem destinatário é bloqueado", r.status_code == 422 and is_open(status(e)))
    f = mk("linkedin_post", "")
    post(f, "approve", "Texto de post")
    check("post sem destinatário é aprovado sem enviar nada", status(f) == "approved" and len(calls) == n1)
    g = mk("send_email", "z@exemplo.com")
    post(g, "reject", "")
    check("rejeitar não envia e marca rejected", status(g) == "rejected" and len(calls) == n1, status(g))
finally:
    cleanup()

print("\nResultado: %d/%d" % (sum(results), len(results)))
sys.exit(0 if results and all(results) else 1)
