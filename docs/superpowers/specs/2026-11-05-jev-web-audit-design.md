# Auditoria SEO com Jev no humberto.ai

## Objetivo aprovado

Criar uma ferramenta nova e gratuita em `/tools/jev-seo-audit`, sem alterar a
ferramenta existente `/tools/url-to-seo-report`. A pessoa informa somente a URL,
acompanha a análise e baixa os mesmos relatórios PDF, Excel e Markdown gerados
pelo runner Python deste repositório. Não há cadastro nem solicitação de chave.

Jev é o único provedor de inteligência artificial desta ferramenta. Não usar a
cascata Gemini/OpenRouter/OpenAI do site nem o binário instalado pelo Cargo.
Reutilizar as verificações determinísticas e o PageSpeed do runner; não incluir
DataForSEO, palavras-chave externas, backlinks ou rastreamento de posições.

## Evidências e limites atuais

- A auditoria real de humberto.ai examinou 60 páginas e levou 5min25s; gerou os
  três formatos apesar de todas as medições PageSpeed terem falhado.
- `jevseo/cli.py:42-123` executa o pipeline e grava `audit.json` e `digest.md`.
  A renderização existente fornece os três formatos; não reconstruir relatórios
  no navegador ou com bibliotecas JavaScript.
- `jevseo/env.py` lê credenciais do ambiente. O serviço usará uma chave própria,
  exclusivamente no servidor, sem credenciais fornecidas pelo visitante.
- Na cópia local `humberto_ai_tools`, `vercel.json` limita a função Express a
  30 segundos. Ela não pode executar a auditoria inteira em uma única chamada.
- Essa cópia é a mais recente das quatro cópias locais inspecionadas, mas sua
  correspondência com a versão publicada ainda não foi confirmada. Antes de
  implementar no site, confirmar o branch atual pelo GitHub autenticado e usar
  um checkout isolado. Não restaurar nem modificar as outras cópias.

## Experiência

1. Página nova, seguindo os componentes e padrões atuais do site, em português.
2. Campo de endereço e botão “Gerar relatório grátis”; nenhum campo de API.
3. Mostrar fila e etapas reais: leitura do site, verificações, Jev, desempenho e
   geração dos arquivos. Não inventar porcentagens ou prazos garantidos.
4. Exibir nota, cobertura de páginas, limitações e três botões de download.
5. Informar que os arquivos ficam disponíveis por 24 horas e permitir nova análise.

“Sempre gerar o relatório” significa tentar produzir os três formatos após uma
auditoria com dados utilizáveis, inclusive quando serviços externos falharem.
Não significa prometer relatório para um site inacessível ou esconder falhas.
Se uma etapa falhar, o relatório deve indicar o que não foi avaliado e marcar a
nota parcial. Se não houver dados suficientes, mostrar uma mensagem explicativa.
Falha de renderização não pode aparecer como sucesso: disponibilizar os arquivos
já gerados e indicar quais falharam, preservando `audit.json` para nova renderização
sem repetir a auditoria paga.

## Implementação mínima

### Site existente

Adicionar rota lazy em `src/App.tsx`, página em `src/pages/tools/`, registro em
`src/data/tools.ts` e conteúdo em `src/data/toolSeo.ts`. Registrar `addedAt` na
data de publicação para aparecer na seção “Novas”. Não trocar o gerador atual.

Usar a API Express existente como ponte curta para criar tarefas, consultar
estado e obter downloads. Segredos da comunicação com o serviço ficam apenas no
backend; nunca em variáveis `VITE_*` ou no bundle do navegador.

### Serviço Python separado

Um serviço hospedado em contêiner, com volume persistente, reaproveita o runner
e o renderizador Python. Uma fila persistida em SQLite e um único executor são
suficientes inicialmente; não adicionar Redis, múltiplos workers ou uma plataforma
de filas sem necessidade. Estado e artefatos ficam em diretórios por tarefa no
volume. A implantação inicial exige uma única instância; escalar horizontalmente
exigirá substituir esses mecanismos por infraestrutura compartilhada.

Cada execução ocorre em processo isolado, com diretório próprio, timeout e
credenciais do ambiente do serviço. Após reinício, tarefas interrompidas são
marcadas como falhas, nunca repetidas automaticamente com novo gasto. A limpeza
periódica remove tarefas e arquivos expirados.

O provedor de hospedagem será escolhido conforme a infraestrutura já disponível;
publicar depende de confirmar capacidade de execução contínua e volume persistente.

### Contrato entre página e backend

- Criar: recebe somente URL; retorna identificador e credencial aleatória de acesso.
- Estado: retorna etapa, cobertura conhecida, avisos e arquivos disponíveis.
- Download: retorna somente um dos três arquivos gerados da tarefa autorizada.
- Estados: aguardando, analisando, gerando arquivos, concluído, parcial ou falhou.
- Consultas e downloads exigem a credencial da tarefa; ela não vai em URL ou logs.
- Uma tarefa só é concluída sem ressalvas quando os três arquivos existem e não
  houve limitação que torne a auditoria parcial.

## Proteções obrigatórias

- Aceitar somente sites HTTP(S) públicos; bloquear credenciais na URL, redes
  privadas, localhost e endpoints de metadados, inclusive após redirects e novas
  resoluções DNS. A checagem atual do crawler não dispensa isolamento de rede.
- Limitar a 60 páginas por auditoria, um executor e 10 tarefas pendentes.
- Limites iniciais: 3 análises por IP em 24 horas, 15 minutos por execução,
  US$ 0,05 de Jev por tarefa e US$ 1 por dia no serviço. Reservar orçamento antes
  de aceitar uma tarefa; não aceitar novas tarefas quando o teto for atingido.
- Não confiar em cabeçalhos de IP enviados pelo visitante; usar somente a cadeia
  de proxy da implantação. Não registrar URLs com segredos ou chaves de API.
- Conteúdo coletado é dado não confiável: não executar instruções da página nem
  inserir seu HTML sem sanitização na interface ou nos relatórios.
- Relatórios não são públicos ou indexáveis; downloads autorizados e sem cache
  compartilhado. Não armazenar o IP bruto com o relatório.
- Chave Jev ausente é erro de configuração do serviço, não convite ao visitante
  para colar uma chave. Não trocar silenciosamente para outro provedor.

## Verificação e critério de entrega

- Testes sem gasto para criação, fila, limites, orçamento, autorização, expiração,
  isolamento entre tarefas, reinício e timeout.
- Testes de segurança para URL privada, redirects privados, re-resolução DNS,
  caminhos de download e conteúdo malicioso.
- Auditoria com integrações simuladas deve produzir PDF, XLSX e Markdown válidos,
  inclusive quando Jev ou PageSpeed falharem parcialmente.
- Fluxo de navegador: URL, progresso real, sucesso/parcial/erro e três downloads;
  verificar teclado e comportamento em celular com o especialista de interface.
- Build e testes relevantes dos dois repositórios, com comandos e resultados
  registrados; um teste real pequeno com Jev após configurar o serviço.
- Confirmar versão do site, hospedagem, segredos e limites antes de publicar.

## Fora do escopo

Contas, pagamentos, planos, histórico permanente, envio por e-mail, chaves do
visitante, DataForSEO, ferramentas extras do CLI Cargo e alterações nas demais
ferramentas do humberto.ai.
