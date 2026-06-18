# 🖥️ HostsMonitor - Dashboard de Monitoramento de Rede

O **HostsMonitor** é uma aplicação desktop moderna desenvolvida em Python para monitoramento e auditoria de segurança de dispositivos de rede em tempo real. 
Com uma interface gráfica limpa e responsiva, o sistema gerencia status de hosts locais, monitora serviços externos (sites/APIs), 
escaneia portas críticas expostas e emite alertas visuais diretamente no sistema operacional.

![Status do Projeto](https://img.shields.io/badge/Status-Conclu%C3%ADdo-brightgreen)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![SQLite](https://img.shields.io/badge/SQLite-3-blue)

---

## 🚀 Funcionalidades Principais

* **Monitoramento em Tempo Real:** Checagem cíclica de latência (ms) e perda de pacotes baseada em ICMP Pings.
* **Escaneamento Automatizado de Portas:** Varredura periódica em background de portas comuns, com atenção especial a portas críticas expostas (`445` - SMB, `3389` - RDP).
* **Filtros Avançados:** Segmentação rápida de dispositivos por setor cadastrado ou por estado (Somente Online, Offline ou em Alerta).
* **Persistência de Dados (SQLite):** Cadastro, edição e exclusão de hosts integrados a um banco de dados local robusto e imune a travamentos de concorrência.
* **Logs de Auditoria:** Registro detalhado com carimbo de data/hora (*timestamp*) de quedas, retornos e vulnerabilidades encontradas.
* **Notificações Nativas:** Alertas no Windows (via balões de notificação) para incidentes críticos na rede.
* **Interface Moderna:** Construída com foco na experiência do usuário, suportando nativamente os modos Escuro (Dark) e Claro (Light) do sistema operacional.

---

## 🛠️ Tecnologias e Ferramentas Utilizadas

* **[CustomTkinter](https://github.com/TomSchimansky/CustomTkinter):** Interface gráfica de usuário (GUI) moderna e customizável.
* **[Ping3](https://github.com/kyan001/ping3):** Utilizada para o envio puro e preciso de pacotes ICMP, calculando latências e perdas sem depender exclusivamente do console do SO.
* **Threading (Módulo Nativo):** Separação estrita entre a linha de processamento da interface visual (Main Thread) e o loop de monitoramento/escaneamento de portas, evitando congelamento do app.
* **SQLite3 (Módulo Nativo):** Mecanismo de persistência local estruturado com conexões isoladas por Thread para garantir a integridade dos dados coletados.
* **[Plyer](https://github.com/kivy/plyer):** Integração com a API do Windows para disparo de notificações *push*.
