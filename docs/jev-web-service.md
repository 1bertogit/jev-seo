# Serviço da auditoria Jev

## O que esta integração entrega

A nova página `/tools/jev-seo-audit` do humberto.ai recebe somente uma URL.
A ponte Express cria uma tarefa no serviço Python, acompanha seu progresso e
entrega os relatórios PDF, Excel e Markdown produzidos pelo runner existente.
O Markdown hospedado inclui seus gráficos no próprio arquivo.

Não utiliza o CLI Cargo, a cascata de IA do navegador, DataForSEO ou uma chave
fornecida pelo visitante. A ferramenta de SEO antiga permanece independente.

## Requisitos para publicação

O serviço precisa de Linux, Bubblewrap com namespaces de usuário funcionando,
`prlimit`, uma única instância e um volume POSIX persistente para SQLite e
artefatos. O processo deve executar sem privilégios administrativos.

Também é obrigatório impor a saída de rede por um proxy validante. Bloquear
acessos diretos e destinos não públicos em IPv4 e IPv6, inclusive localhost,
redes privadas, endereços de metadados e mudanças de DNS após validação. Liberar
somente as exceções operacionais necessárias ao proxy/resolvedor. Uma variável de
ambiente ou uma consulta DNS anterior à conexão não comprova essa contenção.

Se a plataforma impedir Bubblewrap ou não oferecer essa política de rede, ela
não atende aos requisitos desta versão pública. Não usar modo privilegiado,
desativar políticas gerais do host ou executar auditorias sem isolamento para
contornar uma falha de readiness. A renderização JavaScript fica desativada;
páginas que dependem dela são identificadas como cobertura limitada.

O site usa Vercel e a função atual tem limite configurado de 30 segundos. Ela
somente encaminha chamadas curtas; a auditoria de até 15 minutos não roda nela.

## Configuração, sem expor segredos

No serviço Python, configurar pelo gerenciador de segredos da hospedagem:

| Variável | Uso |
| --- | --- |
| `JEV_AUDIT_DATA_DIR` | Caminho absoluto no volume persistente, por exemplo `/data` |
| `JEV_AUDIT_SERVICE_TOKEN` | Segredo aleatório de pelo menos 32 caracteres, compartilhado apenas com a ponte |
| `JEV_AUDIT_TASK_SECRET` | Outro segredo aleatório de pelo menos 32 caracteres, para tokens individuais |
| `TYPESAFE_API_KEY` | Chave Jev dedicada ao serviço, com limite no provedor |
| `PAGESPEED_API_KEY` | Chave opcional do PageSpeed, com quota restrita |
| `JEVSEO_EGRESS_PROXY` | Proxy HTTP(S) confiável com host e porta, sem credenciais na URL |

No backend do site, configurar:

| Variável | Uso |
| --- | --- |
| `JEV_AUDIT_SERVICE_URL` | Origem HTTPS do serviço Python, sem `/v1` ao final |
| `JEV_AUDIT_SERVICE_TOKEN` | Mesmo segredo de comunicação definido no serviço |
| `JEV_AUDIT_IP_SECRET` | Segredo separado, de pelo menos 32 caracteres, para fingerprints de IP |

Nenhuma dessas variáveis usa prefixo `VITE_`. Não colar valores em issues,
relatórios, comandos compartilhados ou arquivos versionados. O worker recebe
somente sua chave Jev/PageSpeed e o ambiente mínimo; não recebe tokens de acesso
do serviço ou de outras tarefas. O modo hospedado nunca procura chaves em `.env`
ou diretórios pessoais.

## Instalação e imagem

Instalação Python do serviço, dentro de um ambiente virtual dedicado:

```sh
python -m pip install '.[web]'
python -m jevseo.web --help
```

A imagem usa somente arquivos selecionados do pacote e bibliotecas necessárias:

```sh
docker build -f docker/web.Dockerfile -t jev-web-audit:local .
```

O comando da imagem escuta na porta 8000. Conectar o volume persistente em
`/data`, montar uma área temporária limitada em `/tmp`, manter a raiz somente
leitura e aplicar os limites de CPU/memória/PIDs da hospedagem. Confirmar que o
UID 10001 consegue escrever no volume. Não publicar a porta sem TLS e sem
verificar a política de rede e a funcionalidade real do sandbox.

O endpoint `/readyz` deve retornar sucesso antes de liberar a página ao público.
Isso não substitui os testes externos de isolamento e rede abaixo.

## Comportamento e limites

- Até 60 páginas por auditoria; 10 tarefas aguardando e um executor.
- Até 3 tarefas aceitas por IP nas últimas 24 horas; falhas contam nesse limite.
- Uma reserva de US$ 0,05 por tarefa, sem devolução; até US$ 1 de reservas por dia
  UTC, portanto no máximo 20 tarefas aceitas diariamente.
- O ledger Jev estima consumo; não substitui o limite de cobrança no provedor.
- Prazo de 900 segundos para auditoria e todas as renderizações juntas.
- Relatórios expiram 24 horas após a criação da tarefa; sem histórico permanente.
- Registros de idempotência duram 48 horas desde a aceitação. Durante esse
  intervalo, uma tentativa expirada retorna conflito, sem repetir o gasto.
- Cada arquivo servido tem limite de 4 MiB, abaixo do limite de payload da ponte.
  Não truncar arquivos maiores nem torná-los públicos como alternativa.

Em Vercel, a ponte usa o IP de plataforma validado; fora dela, ignora headers
forjáveis e usa o socket. Confirmar a cadeia de proxies real antes de publicar,
principalmente se houver CDN adicional à frente da Vercel.

## Falhas e recuperação

Uma falha parcial de Jev, PageSpeed, cobertura ou renderização deve aparecer nos
avisos, sem inventar medições. Cada formato é tentado independentemente. Sem
evidência HTML utilizável, a tarefa falha em vez de produzir uma nota fictícia.

O `audit.json` válido permanece no diretório privado da tarefa até a expiração.
Ele permite renderizar novamente sem repetir a auditoria paga:

```sh
python -m jevseo render /caminho/privado/da/tarefa --formats pdf,xlsx,md
```

Esse comando é para um operador no ambiente protegido, não para aceitar caminhos
enviados pelo visitante. Após renderização manual, validar os arquivos antes de
entregá-los. A API não publica o JSON intermediário, HTML ou diretórios de gráficos.

Após reinício, tarefas em execução viram falhas explícitas; tarefas aguardando
continuam na fila. Não repetir automaticamente chamadas pagas. Os downloads e
consultas exigem token de tarefa em header, nunca na URL.

## Verificação antes de liberar

```sh
python -m pip install -e '.[web,test]'
python -m unittest discover -s tests -v
```

Além dos testes offline, verificar em staging:

1. Os três arquivos reais abrem, e o Markdown não depende de arquivos externos.
2. URLs privadas, redirects privados e rebinding são bloqueados na conexão real.
3. Um worker não consegue ler banco, segredos ou arquivos de outras tarefas.
4. Timeout encerra todos os processos e não trava a fila seguinte.
5. Volume e estado sobrevivem a reinício, sem repetir uma auditoria paga.
6. Tokens incorretos, symlinks, arquivos expirados e formatos arbitrários não
   dão acesso a relatórios.
7. O site consegue criar, acompanhar e baixar via a ponte real, com tamanhos
   representativos e a configuração de proxy da produção.

Só então realizar uma análise pequena com a chave dedicada, conferir consumo e
publicar a nova página. Build local e screenshots com mocks não comprovam uma
implantação pública segura.
