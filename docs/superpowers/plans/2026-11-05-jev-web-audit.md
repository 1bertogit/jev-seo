# Jev Web Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development
> or executing-plans to implement this plan task-by-task. Steps use checkbox
> (`- [ ]`) syntax for tracking.

**Goal:** Entregar uma nova auditoria gratuita no humberto.ai: URL, progresso e
downloads PDF, XLSX e Markdown usando exclusivamente Jev como IA.

**Architecture:** Reutilizar o runner Python e seus relatórios em um serviço
separado, com fila SQLite persistente e um executor isolado. A nova página React
usa uma ponte Express curta; a auditoria nunca roda dentro da função Vercel.
Publicação exige validação da versão do site e contenção real de rede do worker.

**Tech Stack:** Python 3.10+, SQLite, subprocessos, renderizadores existentes,
FastAPI/Uvicorn como extra opcional do serviço; React/TypeScript/Express existentes.

## Global Constraints

- Especificação: `docs/superpowers/specs/2026-11-05-jev-web-audit-design.md`.
- Não alterar a ferramenta `/tools/url-to-seo-report` nem usar o CLI Cargo.
- URL apenas, sem cadastro ou chave do visitante; Jev é a única IA desta ferramenta.
- 60 páginas, 3 análises/IP/24h, 10 tarefas na fila, um executor, prazo total de
  900 segundos e expiração dos relatórios em 24 horas.
- Reservar US$ 0,05/tarefa, sem devolução; reserva diária máxima de US$ 1.
- Chaves somente no servidor. Sem segredos em `VITE_*`, URLs, relatórios ou logs.
- Manter modificações locais alheias intactas. Nunca restaurar a cópia `humberto.ai`.
- Cada executor valida sua área; o orquestrador reconcilia e roda os testes finais
  uma única vez após todos os escritores, registrando comandos e códigos de saída.

## File map and ownership

### Repositório Python: `jev-seo`

- `jevseo/report/{pdf,xlsx,md,__init__}.py`, `jevseo/templates/report.html.j2`:
  relatórios seguros e geração independente de formatos. Responsável: fixer.
- `jevseo/score.py`: cobertura parcial explícita, preservando a pontuação atual.
- `jevseo/web/config.py`: configuração operacional e limites fixos iniciais.
- `jevseo/web/store.py`: admissão transacional, estado e expiração em SQLite.
- `jevseo/web/runner.py`: processo por tarefa, progresso e coleta de artefatos.
- `jevseo/web/app.py`: API autenticada e ciclo de vida do executor único.
- `jevseo/web/security.py`: validação de URL e de artefatos; sem promessa de
  resolver rebinding apenas com pré-validação DNS.
- `tests/test_report_security.py`, `tests/test_web_store.py`,
  `tests/test_web_runner.py`, `tests/test_web_api.py`: testes offline por área.
- `pyproject.toml`: dependências opcionais `web`, sem mudar o CLI padrão.
- `docker/web.Dockerfile`, `docs/jev-web-service.md`: imagem e operação restrita.

### Repositório do site: checkout atual confirmado de `1bertogit/humberto-ai-tools`

- `api/routes/jevAudit.ts`, `tests/api/jevAudit.test.ts`: ponte curta autenticada.
- `api/routes/api.ts`, `.env.example`: registro e nomes de configuração.
- `src/pages/tools/JevSeoAudit.tsx`, `src/services/jevAuditService.ts`:
  interface e cliente da API. Responsável visual: designer.
- `src/App.tsx`, `src/data/tools.ts`, `src/data/toolSeo.ts`: registro lazy, card,
  descrição honesta e `addedAt` na publicação. Responsável: designer.
- `e2e/jev-audit.spec.ts`: experiência de URL até os três downloads, com API simulada.

Não permitir escrita simultânea em arquivos compartilhados: primeiro relatórios,
depois serviço Python. Ponte Express e interface podem ocorrer em paralelo com
contrato fixo, sem compartilhar arquivos de registro.

## HTTP contract

Publicamente, a ponte usa `/api/v1/jev-audit/jobs`; internamente, `/v1/jobs`.
Erros têm `{ "error": { "code": "...", "message": "..." } }` sem detalhes secretos.
Express envia a credencial interna do serviço por HTTPS; o navegador nunca a recebe.

```ts
type AuditState = 'queued' | 'auditing' | 'rendering' | 'completed' | 'partial' | 'failed';
type ReportFormat = 'pdf' | 'xlsx' | 'md';
type AcceptedAudit = { jobId: string; token: string; expiresAt: string };
type AuditStatus = {
  jobId: string;
  state: AuditState;
  stage: string;
  pagesCrawled: number | null;
  score: number | null;
  warnings: string[];
  files: ReportFormat[];
  expiresAt: string;
};
```

- `POST /jobs`: corpo `{ "url": "https://example.org/" }`, cabeçalho
  `Idempotency-Key` gerado uma vez por submissão. Retorna 202 e `AcceptedAudit`.
- `GET /jobs/:id`: retorna `AuditStatus`. Credencial da tarefa em header.
- `GET /jobs/:id/files/:format`: arquivo autorizado; sem caminhos arbitrários.
- Usar `Authorization: Bearer <task-token>` no navegador. A ponte troca esse header
  pela credencial interna e encaminha o token como `X-Job-Token` ao Python.
- Express calcula fingerprint HMAC do IP normalizado a partir da cadeia de proxy
  verificada; Python não aceita IP ou fingerprint de chamadas não autenticadas.
- 400 entrada inválida; 401/404 acesso não autorizado; 409 conflito idempotente;
  429 limite; 503 configuração/serviço indisponível; 410 tarefa expirada.
- Respostas privadas com `no-store`, `nosniff` e `noindex`. Arquivos sempre attachment.

## Task 1: Establish safe source baselines

**Owner:** explorer read-only, depois orquestrador. **Depends on:** nada.

- [ ] Confirmar via GitHub autenticado o branch padrão e SHA remoto; não assumir
  que a branch local apagada do remoto representa produção.
- [ ] Ler instruções canônicas e identificar o checkout que realmente corresponde
  à implantação. Criar worktrees isoladas sem tocar nas quatro cópias existentes.
- [ ] Registrar comandos de testes, versão da fonte e configuração da hospedagem.
- [ ] Se o acesso remoto falhar, continuar só as partes Python independentes;
  bloquear mudanças/publicação do site até confirmar a fonte correta.

Read-only evidence:

```sh
gh api repos/1bertogit/humberto-ai-tools --jq '{default_branch,pushed_at}'
git status --short --branch
git worktree list --porcelain
```

## Task 2: Harden reports and preserve partial output

**Owner:** fixer, escopo de relatórios Python. **Depends on:** worktree Python.

**Interfaces:** preservar `build(folder: Path, formats: list[str], log=print)` e
`write_pdf`, `write_xlsx`, `write_md`. Acrescentar geração independente por formato
no executor hospedado sem transformar falha em sucesso no CLI existente.

- [ ] Criar teste vermelho de fórmula em título/H1 e verificar que o conteúdo
  exportado é texto; fórmulas legítimas do Summary continuam fórmulas.
- [ ] Criar teste vermelho bloqueando URL de rede/arquivo arbitrário no PDF;
  fontes empacotadas e gráficos gerados continuam funcionando.
- [ ] Criar teste vermelho de Markdown com imagem remota/HTML em evidência;
  escapar texto não confiável sem destruir os links intencionais do relatório.
- [ ] Corrigir nos caminhos compartilhados de escrita, sem reimplementar relatórios.
- [ ] Tornar a redação sobre resumo automático e falta de PageSpeed factual;
  remover atribuição a Claude quando a narrativa for automática.
- [ ] Atualizar avisos de cobertura em `score.py` e relatórios para falhas individuais,
  páginas omitidas, limites e renderização JavaScript indisponível.

Example regression assertion:

```python
from openpyxl import Workbook
from jevseo.report.xlsx import table

book = Workbook()
table(book.active, ['Title'], [['=HYPERLINK("https://evil.invalid")']], [30])
assert book.active['A2'].data_type != 'f'
```

Focused checks before and after:

```sh
.venv/bin/python -m unittest discover -s tests -p test_report_security.py -v
```

Expected: new regression fails before changes and all cases pass afterward.
Orquestrador inspeciona diff e arquivos reais produzidos antes de aceitar a entrega.

## Task 3: Persistent admission and single executor

**Owner:** fixer backend Python. **Depends on:** Task 2 finalizada.

**Interfaces:** `Store.accept(url, client_key, idempotency_key, now) -> dict`,
`Store.claim(now) -> dict | None`, `Store.finish(job_id, state, result) -> None`,
`Store.get(job_id) -> dict | None`, `Store.expire(now) -> list[str]`.
`run_job(job: dict, config, on_progress) -> dict` retorna estado, arquivos,
nota e avisos serializáveis, nunca credenciais ou rastros de exceção públicos.

- [ ] Testar admissão concorrente em SQLite real temporário: 3/IP/24h, fila10,
  reserva50_000 microdólares e limite diário1_000_000. Falhas contam nos limites.
- [ ] Testar mesma chave idempotente: não duplica fila/custo; URL diferente conflita.
- [ ] Implementar transação `BEGIN IMMEDIATE`, fingerprint HMAC separado dos
  relatórios e tokens de tarefa deriváveis com segredo do serviço.
- [ ] Testar exclusão de segundo executor por lease em banco e recuperação de
  tarefas interrompidas como falhas, sem repetir chamadas pagas.
- [ ] Implementar subprocesso sem shell, cwd da tarefa, ambiente mínimo,
  `--max-pages 60 --jev-pages 60 --jev-budget 0.05 --render never`, sem `--full`.
- [ ] Usar prazo monotônico total de900s, encerrar grupo de processos e manter
  logs limitados sem parâmetros secretos de URLs.
- [ ] Validar `audit.json` e exigir ao menos uma página HTML utilizável. Preservar
  esse arquivo e tentar cada renderização independentemente dentro do prazo restante.
- [ ] Verificar assinaturas/conteúdo dos três arquivos; renderizações parciais
  preservam arquivos bons e registram falhas sem reexecutar a auditoria.
- [ ] Fazer expiração remover diretório e acesso após24h sem seguir symlinks.

Focused checks:

```sh
.venv/bin/python -m unittest discover -s tests -p test_web_store.py -v
.venv/bin/python -m unittest discover -s tests -p test_web_runner.py -v
```

Sem rede: fake executável controlado pelos testes cria fixtures e simula timeout,
falha de auditoria, PDF falho com XLSX/MD bons e reinício. Todos devem passar.

## Task 4: Authenticated service and restricted execution

**Owner:** fixer backend Python. **Depends on:** Task 3.

**Interfaces:** `create_app(config) -> FastAPI`, CLI
`python -m jevseo.web` em uma instância/um processo servidor; HTTP contract acima.

- [ ] Adicionar extra opcional FastAPI/Uvicorn, mantendo instalação comum intacta.
- [ ] Testar endpoints com dependências simuladas: chave ausente, URL inválida,
  autenticação, idempotência, limites, estado, expiração e downloads entre tarefas.
- [ ] Implementar validação canônica HTTP(S), portas80/443, sem userinfo/controles,
  limites de comprimento e todos os IPs DNS globais. Aplicar aos destinos derivados.
- [ ] Limitar respostas descomprimidas, número de requests e volume total no modo
  hospedado; marcar qualquer truncamento nos dados usados pelo relatório.
- [ ] Exigir configuração de contenção de egress do ambiente hospedado; não
  apresentar a pré-validação DNS ou uma variável de confirmação como sandbox.
- [ ] Restringir PDF a recursos locais aprovados e negar leitura fora da tarefa;
  utilizar imagem não-root, filesystem raiz somente-leitura e limites de recursos.
- [ ] Adicionar documentação exata de volume, executor único, segredos, rede,
  limites no provedor e procedimento de renderização offline sem novo gasto.

Focused checks:

```sh
.venv/bin/python -m unittest discover -s tests -p test_web_api.py -v
.venv/bin/python -m jevseo.web --help
```

Sem gastos nem instalação de infraestrutura na máquina do usuário. A imagem
deve falhar fechada com configuração incompleta e a documentação deve separar
claramente testes locais de condições necessárias à exposição pública.

## Task 5: Existing-site bridge and dedicated interface

**Owners:** fixer Express e designer React, escopos distintos.
**Depends on:** fonte do site confirmada e HTTP contract fixo. Usar mocks até API pronta.

- [ ] Fixer cria testes Supertest para encaminhamento autenticado, IP confiável,
  idempotência, timeouts, erros e downloads; corpo aceita só URL.
- [ ] Fixer implementa ponte com limite de resposta, sem chave pública, sem proxy
  de caminho arbitrário e sem logging de tokens. Nunca executa a auditoria ali.
- [ ] Designer cria página nova com URL, progresso real, avisos e downloads por
  `fetch` autenticado + object URL; nunca token em link/query string.
- [ ] Designer inclui retry seguro para criação, polling sem sobreposição,
  timeout/interrupção, expiração e recuperação de tarefa na mesma sessão.
- [ ] Designer registra rota, catálogo, SEO e data de publicação; sem chamar
  a cascata de IA do navegador e sem alterar a ferramenta de SEO existente.
- [ ] Designer verifica desktop/celular/teclado. Orquestrador revisa apenas copy
  depois do design, sem alterar escolhas visuais.

Frontend integration scenarios:

```ts
await page.route('**/api/v1/jev-audit/jobs', route => route.fulfill({
  status: 202, json: { jobId: 'job-1', token: 'test-token', expiresAt: '2026-11-06T12:00:00Z' },
}));
await page.goto('/tools/jev-seo-audit');
await page.getByLabel('Endereço do site').fill('https://example.org/');
await page.getByRole('button', { name: 'Gerar relatório grátis' }).click();
```

Completar fixtures de estado e arquivos nos testes, sem rede externa. Rodar
Vitest somente nos testes da ponte/cliente e Playwright somente no spec novo.
Não rodar a suíte inteira em cada lane; reportar comando, exit code e evidência.

## Task 6: Reconcile, validate and publish only when safe

**Owner:** orquestrador; publicação separada de implementação.

- [ ] Inspecionar todos os diffs e artefatos reais; devolver ajustes ao mesmo
  especialista. Confirmar que evidências de testes não foram invalidadas por edições.
- [ ] Rodar uma vez a suíte offline Python após reconciliar todos os escritores:

```sh
.venv/bin/python -m unittest discover -s tests -v
```

- [ ] Rodar build, typecheck e testes relevantes do site com comandos extraídos
  do `package.json` confirmado; executar o spec novo de navegador.
- [ ] Validar deploy em staging: saída privada negada IPv4/IPv6, redirects e DNS
  rebinding bloqueados na conexão real, worker sem acesso a tarefas alheias,
  timeout, persistência após reinício e tamanho dos downloads na hospedagem.
- [ ] Se downloads ultrapassarem a capacidade Vercel, não expor arquivos públicos:
  usar endpoint direto HTTPS com token em header ou storage privado antes de publicar.
- [ ] Executar uma análise real pequena com Jev, verificar os três arquivos e
  conferir custo e avisos; não repetir auditorias para corrigir renderização.
- [ ] Publicar somente após confirmar branch, host, volume, egress, chaves e
  cadeia de IP; se faltar acesso, entregar implementação testada e listar o bloqueio.
- [ ] Registrar comandos, exit codes e limitações sem declarar produção pronta
  com base somente em mocks ou em build local.
