🖥️ HostsMonitor - Dashboard de Monitoramento de Rede

O HostsMonitor é uma aplicação desktop desenvolvida em Python para monitoramento contínuo de dispositivos, serviços e recursos de rede. Com uma interface moderna e intuitiva, o sistema permite acompanhar a disponibilidade de hosts internos, monitorar serviços externos através de testes de conectividade e disponibilidade web, identificar portas críticas expostas e registrar eventos de segurança em tempo real.

![Status do Projeto](https://img.shields.io/badge/Status-Conclu%C3%ADdo-brightgreen)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![SQLite](https://img.shields.io/badge/SQLite-3-blue)

🚀 Funcionalidades Principais

📡 Monitoramento de Hosts Internos
Verificação contínua de disponibilidade utilizando ICMP Ping.
Exibição de latência em milissegundos (ms).
Cálculo automático de percentual de perda de pacotes.
Dashboard com indicadores de hosts Online, Offline e em Alerta.

🌐 Monitoramento de Serviços Externos
Cadastro de websites, APIs e serviços externos.
Teste de conectividade via ICMP Ping.
Validação real da disponibilidade através de requisições HTTP/HTTPS.
Exibição do código de resposta retornado pelo servidor (200, 301, 404, 500, etc.).
Identificação de falhas de DNS, timeout e indisponibilidade da aplicação.

🔒 Auditoria de Segurança
Escaneamento periódico de portas TCP comuns.
Monitoramento especial de portas críticas:
445/TCP (SMB)
3389/TCP (RDP)
Geração automática de alertas quando portas sensíveis são detectadas expostas.

🗂️ Organização e Filtros
Agrupamento de dispositivos por setor.
Filtro rápido por:
Online
Offline
Em Alerta
Atualização dinâmica da interface sem necessidade de reiniciar o sistema.

💾 Persistência de Dados
Armazenamento local utilizando SQLite.
Cadastro, edição e exclusão de dispositivos monitorados.
Registro permanente de serviços externos monitorados.

📋 Logs de Auditoria
Registro histórico com data e hora de:
Inclusão e remoção de dispositivos.
Quedas de conectividade.
Retorno de hosts ao estado operacional.
Detecção de portas críticas expostas.
Consulta rápida através da aba de auditoria.

🔔 Notificações em Tempo Real
Alertas nativos do Windows.
Notificação automática para eventos críticos de disponibilidade e segurança.

🎨 Interface Moderna
Desenvolvida com CustomTkinter.
Compatível com modo Claro e Escuro.
Layout responsivo e amigável para equipes de TI e suporte.

🛠️ Tecnologias Utilizadas
Tecnologia	Finalidade
Python	Linguagem principal do projeto
CustomTkinter	Interface gráfica moderna
Ping3	Testes ICMP e medição de latência
Requests	Validação de disponibilidade HTTP/HTTPS
SQLite3	Banco de dados local
Threading	Processamento assíncrono e monitoramento em background
Plyer	Notificações nativas do sistema operacional
Socket	Escaneamento de portas TCP

🔍 Tipos de Monitoramento
Hosts Internos
Verificação	Objetivo
ICMP Ping	Verificar conectividade de rede
Latência	Medir tempo de resposta
Perda de Pacotes	Avaliar estabilidade da conexão
Scan de Portas	Detectar exposições de serviços críticos
Serviços Externos
Verificação	Objetivo
ICMP Ping	Confirmar alcance da rede
HTTP/HTTPS Request	Confirmar funcionamento real da aplicação
Código HTTP	Identificar erros de serviço
DNS	Detectar falhas de resolução de nomes

Exemplo:

Serviço	Ping	HTTP
Google	🟢 15 ms	🟢 200
API Corporativa	🟢 20 ms	🔴 500
Portal Cliente	🟢 18 ms	🔴 Timeout

Isso permite identificar situações em que o servidor responde ao ping, mas a aplicação web está indisponível.

🎯 Casos de Uso
Monitoramento de servidores Windows e Linux.
Supervisão de links e equipamentos de rede.
Monitoramento de websites corporativos.
Verificação de disponibilidade de APIs.
Auditoria básica de exposição de serviços.
Acompanhamento de infraestrutura de TI em pequenas e médias empresas.

