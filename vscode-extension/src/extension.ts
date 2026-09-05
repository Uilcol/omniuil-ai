import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

interface OmniuilFinding {
    rule_id: string; severity: string; title: string;
    description: string; recommendation: string;
    file: string; line: number; column: number; snippet: string;
}
interface ScanSummary {
    total: number; critical: number; high: number;
    medium: number; low: number; scan_path: string; duration_ms: number;
}

const SEV_DIAG: Record<string, vscode.DiagnosticSeverity> = {
    CRITICAL: vscode.DiagnosticSeverity.Error,
    HIGH:     vscode.DiagnosticSeverity.Error,
    MEDIUM:   vscode.DiagnosticSeverity.Warning,
    LOW:      vscode.DiagnosticSeverity.Information,
};
const SEV_EMOJI: Record<string, string> = {
    CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵'
};

let diagCol: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;
let outChan: vscode.OutputChannel;
let treeProvider: FindingsProvider;
let lastFindings: OmniuilFinding[] = [];
let lastSummary: ScanSummary | null = null;

export function activate(ctx: vscode.ExtensionContext) {
    diagCol   = vscode.languages.createDiagnosticCollection('omniuil');
    outChan   = vscode.window.createOutputChannel('OmniUil AI');
    statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBar.command = 'omniuil.showReport';
    statusBar.text    = '$(shield) OmniUil AI';
    statusBar.tooltip = 'OmniUil AI — Clique para ver relatório';
    statusBar.show();

    treeProvider = new FindingsProvider();
    vscode.window.registerTreeDataProvider('omniuilFindings', treeProvider);

    ctx.subscriptions.push(
        vscode.commands.registerCommand('omniuil.scanFile',      cmdScanFile),
        vscode.commands.registerCommand('omniuil.scanWorkspace', cmdScanWorkspace),
        vscode.commands.registerCommand('omniuil.scanFolder',    cmdScanFolder),
        vscode.commands.registerCommand('omniuil.showReport',    cmdShowReport),
        vscode.commands.registerCommand('omniuil.configureBinary', cmdConfigBinary),
        vscode.workspace.onDidSaveTextDocument(doc => {
            const cfg = vscode.workspace.getConfiguration('omniuil');
            const langs = ['python','java','go','javascript','typescript','rust','csharp','ruby'];
            if (cfg.get('scanOnSave') && langs.includes(doc.languageId)) {
                runScan(doc.uri.fsPath, false);
            }
        }),
        vscode.workspace.onDidOpenTextDocument(doc => {
            const cfg = vscode.workspace.getConfiguration('omniuil');
            const langs = ['python','java','go','javascript','typescript','rust','csharp','ruby'];
            if (cfg.get('scanOnOpen') && langs.includes(doc.languageId)) {
                runScan(doc.uri.fsPath, false);
            }
        }),
        diagCol, statusBar, outChan,
    );

    outChan.appendLine('OmniUil AI v1.0.0 ativado');
    checkBinary();
}

function getBinary(): string | null {
    const cfg = vscode.workspace.getConfiguration('omniuil');
    const configured = cfg.get<string>('binaryPath','');
    if (configured && fs.existsSync(configured)) return configured;
    const candidates = [
        path.join(os.homedir(),'QSEC','qsec-rust','target','release','qsec'),
        path.join(os.homedir(),'QSEC','qsec-rust','target','release','omniuil-ai'),
        '/usr/local/bin/qsec', '/usr/local/bin/omniuil-ai',
    ];
    for (const c of candidates) { if (fs.existsSync(c)) return c; }
    return null;
}

async function checkBinary() {
    if (!getBinary()) {
        const a = await vscode.window.showWarningMessage(
            'OmniUil AI: Binário não encontrado. Configure o caminho.', 'Configurar', 'Ignorar');
        if (a === 'Configurar') vscode.commands.executeCommand('omniuil.configureBinary');
    } else {
        statusBar.text = '$(shield) OmniUil AI ✓';
    }
}

async function cmdConfigBinary() {
    const r = await vscode.window.showOpenDialog({
        title: 'Selecionar binário OmniUil AI', canSelectMany: false });
    if (r && r[0]) {
        await vscode.workspace.getConfiguration('omniuil')
            .update('binaryPath', r[0].fsPath, vscode.ConfigurationTarget.Global);
        vscode.window.showInformationMessage(`OmniUil AI: Binário configurado ✓`);
        statusBar.text = '$(shield) OmniUil AI ✓';
    }
}

async function cmdScanFile() {
    const e = vscode.window.activeTextEditor;
    if (!e) { vscode.window.showWarningMessage('Nenhum arquivo aberto.'); return; }
    await runScan(e.document.uri.fsPath, false);
}

async function cmdScanWorkspace() {
    const f = vscode.workspace.workspaceFolders;
    if (!f?.length) { vscode.window.showWarningMessage('Nenhum workspace aberto.'); return; }
    await runScan(f[0].uri.fsPath, true);
}

async function cmdScanFolder() {
    const r = await vscode.window.showOpenDialog({
        title: 'Selecionar pasta', canSelectFolders: true, canSelectMany: false });
    if (r && r[0]) await runScan(r[0].fsPath, true);
}

function runScan(target: string, isDir: boolean): Promise<void> {
    return new Promise(resolve => {
        const bin = getBinary();
        if (!bin) {
            vscode.window.showErrorMessage('OmniUil AI: Binário não encontrado.');
            resolve(); return;
        }
        const cfg     = vscode.workspace.getConfiguration('omniuil');
        const minSev  = cfg.get<string>('minSeverity','medium');
        const exclude = cfg.get<string[]>('excludePatterns',[]);
        const args    = ['scan', target, '--format', 'json'];
        if (minSev !== 'low') args.push('--min-severity', minSev);
        if (exclude.length)   args.push('--exclude', exclude.join(','));

        const label = path.basename(target);
        statusBar.text = `$(sync~spin) OmniUil: Scanning ${label}...`;
        statusBar.backgroundColor = undefined;
        outChan.appendLine(`\n[${new Date().toLocaleTimeString()}] Scan: ${target}`);

        const t0  = Date.now();
        const proc = cp.spawn(bin, args);
        let stdout = '', stderr = '';
        proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
        proc.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });

        proc.on('close', () => {
            const ms = Date.now() - t0;
            let findings: OmniuilFinding[] = [];
            try {
                const parsed = JSON.parse(stdout);
                findings = Array.isArray(parsed) ? parsed : (parsed.findings ?? []);
            } catch { outChan.appendLine(`Parse error. Raw: ${stdout.substring(0,300)}`); }

            lastFindings = findings;
            lastSummary = {
                total: findings.length,
                critical: findings.filter(f => f.severity==='CRITICAL').length,
                high:     findings.filter(f => f.severity==='HIGH').length,
                medium:   findings.filter(f => f.severity==='MEDIUM').length,
                low:      findings.filter(f => f.severity==='LOW').length,
                scan_path: target, duration_ms: ms,
            };

            applyDiagnostics(findings, isDir);
            treeProvider.refresh(findings);
            updateStatusBar(lastSummary);
            outChan.appendLine(
                `Concluído: ${lastSummary.total} findings ` +
                `(${lastSummary.critical} CRITICAL, ${lastSummary.high} HIGH) em ${ms}ms`);

            if (lastSummary.critical > 0 || lastSummary.high > 0) {
                vscode.window.showWarningMessage(
                    `OmniUil AI: ${lastSummary.critical} CRITICAL, ${lastSummary.high} HIGH em ${label}`,
                    'Ver Detalhes'
                ).then(a => { if (a==='Ver Detalhes') outChan.show(); });
            } else if (lastSummary.total === 0) {
                vscode.window.showInformationMessage(`OmniUil AI: ✅ Sem vulnerabilidades em ${label}`);
            }
            resolve();
        });

        proc.on('error', err => {
            outChan.appendLine(`Erro: ${err.message}`);
            statusBar.text = '$(shield-x) OmniUil AI: Erro';
            vscode.window.showErrorMessage(`OmniUil AI: ${err.message}`);
            resolve();
        });
    });
}

function applyDiagnostics(findings: OmniuilFinding[], isDir: boolean) {
    if (!isDir) diagCol.clear();
    const byFile = new Map<string, OmniuilFinding[]>();
    for (const f of findings) {
        const file = f.file || '';
        if (!byFile.has(file)) byFile.set(file, []);
        byFile.get(file)!.push(f);
    }
    for (const [file, flist] of byFile) {
        const uri  = vscode.Uri.file(file);
        const diags = flist.map(f => {
            const ln  = Math.max(0, (f.line||1) - 1);
            const col = Math.max(0, (f.column||1) - 1);
            const rng = new vscode.Range(ln, col, ln, col + 60);
            const sev = SEV_DIAG[f.severity] ?? vscode.DiagnosticSeverity.Warning;
            const d   = new vscode.Diagnostic(
                rng, `${SEV_EMOJI[f.severity]??'⚪'} [${f.rule_id}] ${f.title} — ${f.recommendation}`, sev);
            d.source = 'OmniUil AI';
            d.code   = f.rule_id;
            return d;
        });
        diagCol.set(uri, diags);
    }
}

function updateStatusBar(s: ScanSummary) {
    if (s.critical > 0) {
        statusBar.text = `$(shield-x) OmniUil: ${s.critical} CRITICAL`;
        statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    } else if (s.high > 0) {
        statusBar.text = `$(shield) OmniUil: ${s.high} HIGH`;
        statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    } else if (s.total > 0) {
        statusBar.text = `$(shield) OmniUil: ${s.total} findings`;
        statusBar.backgroundColor = undefined;
    } else {
        statusBar.text = '$(shield) OmniUil AI ✅';
        statusBar.backgroundColor = undefined;
    }
}

function cmdShowReport() {
    if (!lastSummary) {
        vscode.window.showInformationMessage('OmniUil AI: Nenhum scan realizado ainda.');
        return;
    }
    const panel = vscode.window.createWebviewPanel(
        'omniuil', 'OmniUil AI — Report', vscode.ViewColumn.Two, { enableScripts: false });
    panel.webview.html = buildHtml(lastFindings, lastSummary);
}

function buildHtml(findings: OmniuilFinding[], s: ScanSummary): string {
    const rows = findings.map(f => `
        <tr><td>${SEV_EMOJI[f.severity]??'⚪'} <b>${f.severity}</b></td>
        <td><code>${f.rule_id}</code></td><td>${f.title}</td>
        <td>${path.basename(f.file||'')}:${f.line}</td>
        <td class="rec">${f.recommendation}</td></tr>`).join('');
    return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<style>
body{font-family:var(--vscode-font-family);background:var(--vscode-editor-background);color:var(--vscode-editor-foreground);padding:20px}
h1{color:#00d4ff;border-bottom:1px solid #1a3a5c;padding-bottom:10px}
.cards{display:flex;gap:12px;margin:16px 0;flex-wrap:wrap}
.card{padding:10px 18px;border-radius:8px;text-align:center;min-width:80px}
.c{background:#2a0a0a;border:1px solid #ff444444;color:#ff4444}
.h{background:#2a1a0a;border:1px solid #ffaa0044;color:#ffaa00}
.m{background:#1a1a0a;border:1px solid #ffff0044;color:#ffff00}
.l{background:#0a1a2a;border:1px solid #00d4ff44;color:#00d4ff}
.t{background:#0a0a2a;border:1px solid #8888ff44;color:#8888ff}
.n{font-size:1.8rem;font-weight:bold}
table{width:100%;border-collapse:collapse;margin-top:16px;font-size:.85rem}
th{background:#0a1628;padding:8px;text-align:left;border-bottom:2px solid #1a3a5c}
td{padding:8px;border-bottom:1px solid #0a1628;vertical-align:top}
.rec{font-size:.78rem;color:#8aaa}code{background:#1a1a2a;padding:1px 4px;border-radius:3px}
.meta{font-size:.72rem;color:#4a6a8a;margin-top:8px}
</style></head><body>
<h1>⚡ OmniUil AI — Security Report</h1>
<div class="meta">📁 ${s.scan_path} | ⏱ ${s.duration_ms}ms</div>
<div class="cards">
  <div class="card c"><div class="n">${s.critical}</div>CRITICAL</div>
  <div class="card h"><div class="n">${s.high}</div>HIGH</div>
  <div class="card m"><div class="n">${s.medium}</div>MEDIUM</div>
  <div class="card l"><div class="n">${s.low}</div>LOW</div>
  <div class="card t"><div class="n">${s.total}</div>TOTAL</div>
</div>
${findings.length===0
  ? '<p style="color:#00e676;font-size:1.1rem">✅ Nenhuma vulnerabilidade detectada.</p>'
  : `<table><thead><tr><th>Severidade</th><th>Regra</th><th>Título</th><th>Local</th><th>Recomendação</th></tr></thead><tbody>${rows}</tbody></table>`}
<div class="meta" style="margin-top:24px">OmniUil AI v1.0.0 — github.com/Uilcol/omniuil-ai | 33 regras NIST FIPS 203/204/205</div>
</body></html>`;
}

class FindingsProvider implements vscode.TreeDataProvider<FindingItem> {
    private _change = new vscode.EventEmitter<void>();
    readonly onDidChangeTreeData = this._change.event;
    private items: OmniuilFinding[] = [];
    refresh(f: OmniuilFinding[]) { this.items = f; this._change.fire(); }
    getTreeItem(e: FindingItem) { return e; }
    getChildren() { return this.items.map(f => new FindingItem(f)); }
}

class FindingItem extends vscode.TreeItem {
    constructor(f: OmniuilFinding) {
        super(`${SEV_EMOJI[f.severity]??'⚪'} ${f.rule_id}: ${f.title}`,
              vscode.TreeItemCollapsibleState.None);
        this.tooltip     = `${f.description}\n\nRecomendação: ${f.recommendation}`;
        this.description = `${path.basename(f.file||'')}:${f.line}`;
        const icons: Record<string,string> = {CRITICAL:'error',HIGH:'warning',MEDIUM:'info',LOW:'lightbulb'};
        this.iconPath = new vscode.ThemeIcon(icons[f.severity]||'circle-outline');
        if (f.file) this.command = {
            command: 'vscode.open', title: 'Abrir',
            arguments: [vscode.Uri.file(f.file),
                { selection: new vscode.Range(Math.max(0,(f.line||1)-1),0,Math.max(0,(f.line||1)-1),0) }]
        };
    }
}

export function deactivate() {}
