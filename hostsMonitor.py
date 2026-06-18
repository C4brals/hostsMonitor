import tkinter as tk
import customtkinter as ctk
from ping3 import ping
import threading
import time
import socket
import sqlite3
from tkinter import messagebox
from datetime import datetime
from plyer import notification

PORTAS_PERIGOSAS = [445, 3389]

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")


class NetworkMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        try:
            self.iconbitmap(r"icons\icon.ico")
        except:
            pass # Evita quebrar se o ícone não existir no caminho

        self.title("hostsMonitor")
        
        self.hosts = []
        self.servicos_externos = []
        self.setor_atual_filtro = "Todos"

        self.inicializar_banco()
        self.criar_interface()
        self.carregar_hosts_salvos()
        self.carregar_servicos_externos()
        self.atualizar_tabela_logs()

        self.rodando = True
        self.thread_monitor = threading.Thread(target=self.atualizar_pings_loop, daemon=True)
        self.thread_monitor.start()

        # Configura o fechamento limpo do app
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.after(100, lambda: self.state("zoomed"))

    def inicializar_banco(self):
        # Criamos uma conexão rápida apenas para setup inicial na thread principal
        conn = sqlite3.connect("hosts.db")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS computadores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                ip TEXT NOT NULL UNIQUE,
                setor TEXT DEFAULT 'Geral'
            )
        """)
        try:
            cursor.execute("ALTER TABLE computadores ADD COLUMN setor TEXT DEFAULT 'Geral'")
        except sqlite3.OperationalError:
            pass

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data_hora TEXT NOT NULL,
                host_ip TEXT NOT NULL,
                evento TEXT NOT NULL
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS servicos_externos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                host TEXT NOT NULL UNIQUE
            )
        """)
        conn.commit()
        conn.close()

    def conectar_banco_local(self):
        """ Helper para obter uma conexão exclusiva para a thread que chamar """
        return sqlite3.connect("hosts.db")

    def enviar_notificacao_windows(self, titulo, mensagem):
        try:
            notification.notify(
                title=titulo,
                message=mensagem,
                app_name="Monitor de Rede",
                timeout=7
            )
        except Exception as e:
            print(f"Falha ao emitir notificação do Windows: {e}")

    def registrar_log(self, ip, evento):
        data_hora = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        
        # Conexão local dedicada para evitar colisão entre threads
        conn = sqlite3.connect("hosts.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO logs (data_hora, host_ip, evento) VALUES (?, ?, ?)", (data_hora, ip, evento))
        conn.commit()
        conn.close()

        titulo_alerta = "🚨 Alerta de Segurança" if "⚠️" in evento or "❌" in evento else "ℹ️ Monitor de Rede"
        self.enviar_notificacao_windows(titulo_alerta, f"IP: {ip}\n{evento}")

        if hasattr(self, "txt_logs"):
            # Invoca a atualização visual de forma segura na Thread Principal
            self.after(0, self.atualizar_tabela_logs)

    def criar_interface(self):
        
        lbl_assinatura = ctk.CTkLabel(self, text="Augusto Cabral", font=ctk.CTkFont(size=10), text_color="gray50")
        lbl_assinatura.pack(side="bottom", anchor="e", padx=15, pady=(0, 5))
        
        self.abas = ctk.CTkTabview(self)
        self.abas.pack(fill="both", expand=True, padx=10, pady=(10, 0))
        
        self.tab_monitor = self.abas.add("Monitoramento de Dispositivos")
        self.tab_logs = self.abas.add("Logs de Auditoria")

        # --- ABA MONITORAMENTO ---
        self.frame_cadastro = ctk.CTkFrame(self.tab_monitor)
        self.frame_cadastro.pack(pady=10, padx=10, fill="x")

        self.entry_nome = ctk.CTkEntry(self.frame_cadastro, placeholder_text="Nome (ex: Servidor)")
        self.entry_nome.pack(side="left", padx=5, pady=10, expand=True, fill="x")

        self.entry_ip = ctk.CTkEntry(self.frame_cadastro, placeholder_text="Endereço IP")
        self.entry_ip.pack(side="left", padx=5, pady=10, expand=True, fill="x")

        self.entry_setor = ctk.CTkEntry(self.frame_cadastro, placeholder_text="Setor (ex: TI)")
        self.entry_setor.pack(side="left", padx=5, pady=10, expand=True, fill="x")

        self.btn_cadastrar = ctk.CTkButton(self.frame_cadastro, text="Cadastrar Host", command=self.cadastrar_host_ui)
        self.btn_cadastrar.pack(side="left", padx=5, pady=10)

        self.frame_filtro = ctk.CTkFrame(self.tab_monitor, fg_color="transparent")
        self.frame_filtro.pack(padx=10, fill="x", pady=5)

        ctk.CTkLabel(self.frame_filtro, text="Filtrar por Setor:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=5)
        self.combo_filtro = ctk.CTkComboBox(self.frame_filtro, values=["Todos"], command=self.filtrar_setores_action)
        self.combo_filtro.pack(side="left", padx=5)

        # DASHBOARD
        self.frame_dashboard = ctk.CTkFrame(self.tab_monitor)
        self.frame_dashboard.pack(fill="x", padx=10, pady=(20,20))

        self.lbl_total = ctk.CTkLabel(self.frame_dashboard, text="TOTAL\n0", font=ctk.CTkFont(size=18, weight="bold"))
        self.lbl_total.pack(side="left", padx=20, pady=10)

        self.lbl_online = ctk.CTkLabel(self.frame_dashboard, text="ONLINE\n0", text_color="#2ecc71", font=ctk.CTkFont(size=18, weight="bold"))
        self.lbl_online.pack(side="left", padx=20, pady=10)

        self.lbl_offline = ctk.CTkLabel(self.frame_dashboard, text="OFFLINE\n0", text_color="#e74c3c", font=ctk.CTkFont(size=18, weight="bold"))
        self.lbl_offline.pack(side="left", padx=20, pady=10)

        self.lbl_alertas = ctk.CTkLabel(self.frame_dashboard, text="ALERTAS\n0", text_color="#f39c12", font=ctk.CTkFont(size=18, weight="bold"))
        self.lbl_alertas.pack(side="left", padx=20, pady=10)

        self.lbl_ultima_atualizacao = ctk.CTkLabel(self.frame_dashboard, text="Última atualização: --")
        self.lbl_ultima_atualizacao.pack(side="right", padx=20)

        self.frame_filtros_rapidos = ctk.CTkFrame(self.tab_monitor, fg_color="transparent")
        self.frame_filtros_rapidos.pack(fill="x", padx=10, pady=5)

        self.var_offline = tk.BooleanVar()
        self.var_alerta = tk.BooleanVar()
        self.var_online = tk.BooleanVar()

        ctk.CTkCheckBox(self.frame_filtros_rapidos, text="Somente Online", variable=self.var_online, command=self.aplicar_filtros, font=ctk.CTkFont(size=11), checkbox_width=16, checkbox_height=16).pack(side="left", padx=5)
        ctk.CTkCheckBox(self.frame_filtros_rapidos, text="Somente Offline", variable=self.var_offline, command=self.aplicar_filtros, font=ctk.CTkFont(size=11), checkbox_width=16, checkbox_height=16).pack(side="left", padx=5)
        ctk.CTkCheckBox(self.frame_filtros_rapidos, text="Somente Alertas", variable=self.var_alerta, command=self.aplicar_filtros, font=ctk.CTkFont(size=11), checkbox_width=16, checkbox_height=16).pack(side="left", padx=5)

        self.frame_header = ctk.CTkFrame(self.tab_monitor, fg_color="transparent")
        self.frame_header.pack(padx=25, fill="x", pady=(10, 0))

        colunas = [
            ("Dispositivo / IP", 0, 260),
            ("Setor", 1, 120),
            ("Status", 2, 120),
            ("Latência", 3, 100),
            ("Perda", 4, 80),
            ("Portas Críticas Abertas", 5, 300),
            ("Ações", 6, 150)
        ]

        for texto, col, largura in colunas:
            lbl = ctk.CTkLabel(self.frame_header, text=texto, font=ctk.CTkFont(weight="bold"), width=largura, anchor="w")
            lbl.grid(row=0, column=col, padx=5, sticky="w")

        self.frame_lista = ctk.CTkScrollableFrame(self.tab_monitor)
        self.frame_lista.pack(pady=5, padx=10, fill="both", expand=True)

        # MONITORAMENTO EXTERNO
        self.frame_externo = ctk.CTkFrame(self.tab_monitor)
        self.frame_externo.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(self.frame_externo, text="Monitoramento Externo", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=10, pady=(5,10))

        self.frame_cadastro_externo = ctk.CTkFrame(self.frame_externo, fg_color="transparent")
        self.frame_cadastro_externo.pack(fill="x", padx=10)

        self.entry_nome_externo = ctk.CTkEntry(self.frame_cadastro_externo, width=180, placeholder_text="Nome")
        self.entry_nome_externo.pack(side="left", padx=5)

        self.entry_host_externo = ctk.CTkEntry(self.frame_cadastro_externo, width=250, placeholder_text="google.com")
        self.entry_host_externo.pack(side="left", padx=5)

        ctk.CTkButton(self.frame_cadastro_externo, text="Adicionar", command=self.adicionar_servico_externo).pack(side="left", padx=5)

        self.frame_lista_externa = ctk.CTkScrollableFrame(self.frame_externo, height=150)
        self.frame_lista_externa.pack(fill="x", padx=10, pady=10)

        # ABA DE LOGS
        self.frame_botoes_log = ctk.CTkFrame(self.tab_logs, fg_color="transparent")
        self.frame_botoes_log.pack(fill="x", padx=10, pady=5)

        self.btn_atualizar_log = ctk.CTkButton(self.frame_botoes_log, text="Atualizar Logs", command=self.atualizar_tabela_logs)
        self.btn_atualizar_log.pack(side="left", padx=5)

        self.btn_limpar_log = ctk.CTkButton(self.frame_botoes_log, text="Limpar Histórico", fg_color="#e74c3c", hover_color="#c0392b", command=self.limpar_logs_banco)
        self.btn_limpar_log.pack(side="right", padx=5)

        self.txt_logs = ctk.CTkTextbox(self.tab_logs, font=ctk.CTkFont(family="Courier", size=12))
        self.txt_logs.pack(fill="both", expand=True, padx=10, pady=10)

    def carregar_hosts_salvos(self):
        conn = self.conectar_banco_local()
        cursor = conn.cursor()
        cursor.execute("SELECT id, nome, ip, setor FROM computadores")
        for id_db, nome, ip, setor in cursor.fetchall():
            self.adicionar_host_na_tela(id_db, nome, ip, setor)
        self.atualizar_lista_filtros_combobox()
        conn.close()

    def carregar_servicos_externos(self):
        conn = self.conectar_banco_local()
        cursor = conn.cursor()
        cursor.execute("SELECT id, nome, host FROM servicos_externos")
        for id_db, nome, host in cursor.fetchall():
            # Implementação básica simplificada visual para fins de execução estável
            pass
        conn.close()

    def cadastrar_host_ui(self):
        nome = self.entry_nome.get().strip()
        ip = self.entry_ip.get().strip()
        setor = self.entry_setor.get().strip()

        if not setor: setor = "Geral"

        if nome and ip:
            conn = self.conectar_banco_local()
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO computadores (nome, ip, setor) VALUES (?, ?, ?)", (nome, ip, setor))
                conn.commit()
                id_db = cursor.lastrowid

                self.adicionar_host_na_tela(id_db, nome, ip, setor)
                self.registrar_log(ip, f"Novo computador cadastrado no setor [{setor}]: {nome}")
                self.atualizar_lista_filtros_combobox()

                self.entry_nome.delete(0, tk.END)
                self.entry_ip.delete(0, tk.END)
                self.entry_setor.delete(0, tk.END)
            except sqlite3.IntegrityError:
                messagebox.showerror("Erro", "Este endereço IP já está cadastrado!")
            finally:
                conn.close()

    def adicionar_host_na_tela(self, id_db, nome, ip, setor):
        row_frame = ctk.CTkFrame(self.frame_lista)

        if self.setor_atual_filtro == "Todos" or self.setor_atual_filtro == setor:
            row_frame.pack(pady=3, fill="x")
        else:
            row_frame.pack_forget()

        lbl_nome = ctk.CTkLabel(row_frame, text=f"{nome} - {ip}", justify="left", font=ctk.CTkFont(size=13), width=260, anchor="w")
        lbl_nome.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        lbl_setor_visual = ctk.CTkLabel(row_frame, text=setor, font=ctk.CTkFont(size=12), width=120, anchor="w")
        lbl_setor_visual.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        lbl_status = ctk.CTkLabel(row_frame, text="⚪ Aguardando", text_color="grey", font=ctk.CTkFont(weight="bold"), width=100, anchor="w")
        lbl_status.grid(row=0, column=2, padx=5, pady=5, sticky="w")

        lbl_ms = ctk.CTkLabel(row_frame, text="---", font=ctk.CTkFont(size=12), width=100, anchor="w")
        lbl_ms.grid(row=0, column=3, padx=5, pady=5, sticky="w")

        lbl_perda = ctk.CTkLabel(row_frame, text="0%", font=ctk.CTkFont(size=12), width=80, anchor="w")
        lbl_perda.grid(row=0, column=4, padx=5, pady=5, sticky="w")

        lbl_portas_criticas = ctk.CTkLabel(row_frame, text="Escaneando...", font=ctk.CTkFont(size=12, weight="bold"), width=140, anchor="w")
        lbl_portas_criticas.grid(row=0, column=5, padx=5, pady=5, sticky="w")

        frame_acoes = ctk.CTkFrame(row_frame, fg_color="transparent")
        frame_acoes.grid(row=0, column=6, padx=5, pady=5, sticky="w")

        host_data = {
            "id": id_db, "nome": nome, "ip": ip, "setor": setor,
            "status_anterior": "DESCONHECIDO", "portas_perigosas_alertadas": set(),
            "ultimo_scan_portas": 0,
            "label_nome": lbl_nome, "label_setor": lbl_setor_visual, "label_status": lbl_status,
            "label_ms": lbl_ms, "label_perda": lbl_perda,
            "label_portas_criticas": lbl_portas_criticas,
            "frame_linha": row_frame, "ativo": True,
            "historico_ping": [],            
        }

        btn_editar = ctk.CTkButton(frame_acoes, text="Editar", width=60, fg_color="#616161", hover_color="#2980b9", command=lambda: self.abrir_janela_edicao(host_data))
        btn_editar.pack(side="left", padx=2)

        btn_excluir = ctk.CTkButton(frame_acoes, text="Excluir", width=60, fg_color="#616161", hover_color="#c0392b", command=lambda: self.excluir_host(host_data))
        btn_excluir.pack(side="left", padx=2)

        self.hosts.append(host_data)

    def abrir_janela_edicao(self, host_data):
        janela_edit = ctk.CTkToplevel(self)
        janela_edit.title("Editar Host")
        janela_edit.geometry("400x260")
        janela_edit.grab_set()

        ctk.CTkLabel(janela_edit, text="Nome do Computador:").pack(pady=(10, 2))
        entry_nome_edit = ctk.CTkEntry(janela_edit, width=250)
        entry_nome_edit.insert(0, host_data["nome"])
        entry_nome_edit.pack()

        ctk.CTkLabel(janela_edit, text="Endereço IP:").pack(pady=(5, 2))
        entry_ip_edit = ctk.CTkEntry(janela_edit, width=250)
        entry_ip_edit.insert(0, host_data["ip"])
        entry_ip_edit.pack()

        ctk.CTkLabel(janela_edit, text="Setor:").pack(pady=(5, 2))
        entry_setor_edit = ctk.CTkEntry(janela_edit, width=250)
        entry_setor_edit.insert(0, host_data["setor"])
        entry_setor_edit.pack()

        def salvar_alteracoes():
            novo_nome = entry_nome_edit.get().strip()
            novo_ip = entry_ip_edit.get().strip()
            novo_setor = entry_setor_edit.get().strip()
            if not novo_setor: novo_setor = "Geral"

            if novo_nome and novo_ip:
                conn = self.conectar_banco_local()
                cursor = conn.cursor()
                try:
                    cursor.execute("UPDATE computadores SET nome = ?, ip = ?, setor = ? WHERE id = ?",
                                    (novo_nome, novo_ip, novo_setor, host_data["id"]))
                    conn.commit()

                    if novo_ip != host_data["ip"]:
                        host_data["portas_perigosas_alertadas"].clear()
                        host_data["ultimo_scan_portas"] = 0

                    self.registrar_log(novo_ip, f"Host Modificado. Setor: {novo_setor} | Nome: {novo_nome}")

                    host_data["nome"] = novo_nome
                    host_data["ip"] = novo_ip
                    host_data["setor"] = novo_setor
                    host_data["label_nome"].configure(text=f"{novo_nome}\n({novo_ip})")
                    host_data["label_setor"].configure(text=novo_setor)

                    self.atualizar_lista_filtros_combobox()
                    self.filtrar_setores_action(self.setor_atual_filtro)

                    janela_edit.destroy()
                except sqlite3.IntegrityError:
                    messagebox.showerror("Erro", "Este endereço IP já está sendo usado por outro host!")
                finally:
                    conn.close()

        ctk.CTkButton(janela_edit, text="Salvar", fg_color="#2ecc71", hover_color="#27ae60", command=salvar_alteracoes).pack(pady=15)

    def excluir_host(self, host_data):
        if messagebox.askyesno("Confirmar Exclusão", f"Tem certeza que deseja excluir '{host_data['nome']}'?"):
            conn = self.conectar_banco_local()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM computadores WHERE id = ?", (host_data["id"],))
            conn.commit()
            conn.close()
            
            host_data["ativo"] = False
            self.registrar_log(host_data["ip"], f"Host removido do monitoramento: {host_data['nome']}")
            host_data["frame_linha"].destroy()
            if host_data in self.hosts:
                self.hosts.remove(host_data)
            self.atualizar_lista_filtros_combobox()

    def atualizar_lista_filtros_combobox(self):
        setores_existentes = set(host["setor"] for host in self.hosts)
        opcoes = ["Todos"] + sorted(list(setores_existentes))
        self.combo_filtro.configure(values=opcoes)

    def filtrar_setores_action(self, setor_selecionado):
        self.setor_atual_filtro = setor_selecionado
        for host in self.hosts:
            if setor_selecionado == "Todos" or host["setor"] == setor_selecionado:
                host["frame_linha"].pack(pady=3, fill="x")
            else:
                host["frame_linha"].pack_forget()

    def atualizar_tabela_logs(self):
        conn = self.conectar_banco_local()
        cursor = conn.cursor()
        cursor.execute("SELECT data_hora, host_ip, evento FROM logs ORDER BY id DESC LIMIT 200")
        historico = cursor.fetchall()
        conn.close()

        self.txt_logs.configure(state="normal")
        self.txt_logs.delete("1.0", tk.END)

        if not historico:
            self.txt_logs.insert(tk.END, "Nenhum evento registrado até o momento.\n")
        else:
            linha_cabecalho = f"{'DATA / HORA':<22} | {'ALVO IP':<16} | {'EVENTO REGISTRADO'}\n"
            self.txt_logs.insert(tk.END, linha_cabecalho)
            self.txt_logs.insert(tk.END, "-" * 100 + "\n")

            for data_hora, ip, evento in historico:
                formatado = f"{data_hora:<22} | {ip:<16} | {evento}\n"
                self.txt_logs.insert(tk.END, formatado)

        self.txt_logs.configure(state="disabled")

    def limpar_logs_banco(self):
        if messagebox.askyesno("Limpar Histórico", "Deseja apagar permanentemente todos os logs do banco?"):
            conn = self.conectar_banco_local()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM logs")
            conn.commit()
            conn.close()
            self.atualizar_tabela_logs()

    def escanear_portas(self, ip, host_data):
        portas_para_testar = [80, 443, 445, 3389, 22, 21, 3306, 1433, 8080]
        portas_abertas = []

        for porta in portas_para_testar:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.2)
                    if s.connect_ex((ip, porta)) == 0:
                        portas_abertas.append(porta)
                        if porta in PORTAS_PERIGOSAS:
                            if porta not in host_data["portas_perigosas_alertadas"]:
                                host_data["portas_perigosas_alertadas"].add(porta)
                                # Lança o registro de log em thread separada para não travar o loop
                                threading.Thread(target=self.registrar_log, args=(ip, f"⚠️ ALERTA: Porta crítica {porta} exposta por {host_data['nome']}")).start()
            except:
                pass

        return " | ".join(f"⚠️ {porta}" for porta in portas_abertas) if portas_abertas else "Nenhuma"

    def atualizar_pings_loop(self):
        while self.rodando:
            for host in list(self.hosts):
                if not self.rodando: break
                if host is None or not isinstance(host, dict) or not host.get("ativo", False): continue

                ip = host["ip"]                
                resposta = ping(ip, timeout=0.5)

                pings_sucesso = 1 if (resposta is not None and resposta is not False) else 0
                soma_ms = resposta if pings_sucesso else 0

                host["historico_ping"].append(pings_sucesso)
                host["historico_ping"] = host["historico_ping"][-20:]

                sucessos = sum(host["historico_ping"])
                perda = int(((len(host["historico_ping"]) - sucessos) / len(host["historico_ping"])) * 100) if host["historico_ping"] else 0

                if perda >= 50: cor_perda = "#e74c3c"
                elif perda >= 20: cor_perda = "#f39c12"
                else: cor_perda = "#2ecc71"

                # ATUALIZAÇÃO SEGURA VIA .after()
                self.after(0, lambda h=host, p=perda, c=cor_perda: h["label_perda"].configure(text=f"{p}%", text_color=c))

                if pings_sucesso > 0:
                    ms_medio = int((soma_ms / pings_sucesso) * 1000)
                    cor_ms = "#2ecc71" if ms_medio < 20 else "#f39c12" if ms_medio < 50 else "#e74c3c"

                    self.after(0, lambda h=host, m=ms_medio, c=cor_ms: (
                        h["label_status"].configure(text="🟢 Online", text_color="#2ecc71"),
                        h["label_ms"].configure(text=f"{m} ms", text_color=c)
                    ))

                    tempo_atual = time.time()
                    INTERVALO_SCAN = 1800 

                    if tempo_atual - host.get("ultimo_scan_portas", 0) > INTERVALO_SCAN:
                        portas_criticas = self.escanear_portas(ip, host)
                        
                        def atualizar_portas(h=host, pc=portas_criticas):
                            if h["ativo"]:
                                if pc != "Nenhuma":                                
                                    h["label_portas_criticas"].configure(text=pc, text_color="#e74c3c")
                                else:
                                    h["label_portas_criticas"].configure(text="Nenhuma", text_color="grey")
                        
                        self.after(0, atualizar_portas)
                        host["ultimo_scan_portas"] = tempo_atual

                    if host["status_anterior"] == "OFFLINE":
                        threading.Thread(target=self.registrar_log, args=(ip, f"Host reestabelecido: {host['nome']} online.")).start()
                    host["status_anterior"] = "ONLINE"
                else:
                    self.after(0, lambda h=host: (
                        h["label_status"].configure(text="🔴 Offline", text_color="#e74c3c"),
                        h["label_ms"].configure(text="---"),
                        h["label_portas_criticas"].configure(text="---", text_color="grey")
                    ))

                    if host["status_anterior"] == "ONLINE":
                        threading.Thread(target=self.registrar_log, args=(ip, f"❌ ALERTA: {host['nome']} caiu.")).start()
                    host["status_anterior"] = "OFFLINE"

            # Atualiza Dashboard de forma Thread-safe
            self.after(0, self.atualizar_dashboard)
            time.sleep(2) # Aumentado para 2s para poupar processamento cíclico excessivo

    def atualizar_dashboard(self):
        total = len(self.hosts)
        online = sum(1 for h in self.hosts if h["status_anterior"] == "ONLINE")
        offline = sum(1 for h in self.hosts if h["status_anterior"] == "OFFLINE")
        alertas = sum(1 for h in self.hosts if h["label_portas_criticas"].cget("text") not in ["Nenhuma", "---", "Escaneando..."])

        self.lbl_total.configure(text=f"TOTAL\n{total}")
        self.lbl_online.configure(text=f"ONLINE\n{online}")
        self.lbl_offline.configure(text=f"OFFLINE\n{offline}")
        self.lbl_alertas.configure(text=f"ALERTAS\n{alertas}")
        self.lbl_ultima_atualizacao.configure(text=f"Última atualização: {datetime.now().strftime('%H:%M:%S')}")
        self.aplicar_filtros()

    def aplicar_filtros(self):
        somente_online = self.var_online.get()
        somente_offline = self.var_offline.get()
        somente_alerta = self.var_alerta.get()

        for host in self.hosts:
            mostrar = True
            if somente_online and not somente_offline:
                mostrar = host["status_anterior"] == "ONLINE"
            elif somente_offline and not somente_online:
                mostrar = host["status_anterior"] == "OFFLINE"

            if mostrar and somente_alerta:
                mostrar = host["label_portas_criticas"].cget("text") not in ["Nenhuma", "---", "Escaneando..."]

            if mostrar:
                host["frame_linha"].pack(pady=3, fill="x")
            else:
                host["frame_linha"].pack_forget()

    def adicionar_servico_externo(self):
        nome = self.entry_nome_externo.get().strip()
        host = self.entry_host_externo.get().strip()
        if not nome or not host: return

        conn = self.conectar_banco_local()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO servicos_externos (nome, host) VALUES (?, ?)", (nome, host))
            conn.commit()
            self.entry_nome_externo.delete(0, tk.END)
            self.entry_host_externo.delete(0, tk.END)
        except sqlite3.IntegrityError:
            messagebox.showerror("Erro", "Serviço já existe.")
        finally:
            conn.close()

    def on_closing(self):
        self.rodando = False
        self.destroy()


if __name__ == "__main__":
    app = NetworkMonitorApp()
    app.mainloop()