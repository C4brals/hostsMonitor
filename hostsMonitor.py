import tkinter as tk
import customtkinter as ctk
from ping3 import ping
import threading
import time
import socket
from scapy.all import ARP, Ether, srp
import sqlite3
from tkinter import messagebox
from datetime import datetime
from plyer import notification
import psutil

PORTAS_PERIGOSAS = [445, 3389]

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")


class NetworkMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Monitor de Rede & Firewall Auditor")
        self.geometry("1200x700")

        self.hosts = []
        self.setor_atual_filtro = "Todos"

        self.inicializar_banco()
        self.criar_interface()
        self.carregar_hosts_salvos()
        self.atualizar_tabela_logs()

        self.rodando = True
        self.thread_monitor = threading.Thread(target=self.atualizar_pings_loop, daemon=True)
        self.thread_monitor.start()

    def inicializar_banco(self):
        self.conn = sqlite3.connect("hosts.db", check_same_thread=False)
        self.cursor = self.conn.cursor()

        self.cursor.execute("""
                            CREATE TABLE IF NOT EXISTS computadores
                            (
                                id
                                INTEGER
                                PRIMARY
                                KEY
                                AUTOINCREMENT,
                                nome
                                TEXT
                                NOT
                                NULL,
                                ip
                                TEXT
                                NOT
                                NULL
                                UNIQUE,
                                setor
                                TEXT
                                DEFAULT
                                'Geral'
                            )
                            """)
        try:
            self.cursor.execute("ALTER TABLE computadores ADD COLUMN setor TEXT DEFAULT 'Geral'")
        except sqlite3.OperationalError:
            pass

        self.cursor.execute("""
                            CREATE TABLE IF NOT EXISTS logs
                            (
                                id
                                INTEGER
                                PRIMARY
                                KEY
                                AUTOINCREMENT,
                                data_hora
                                TEXT
                                NOT
                                NULL,
                                host_ip
                                TEXT
                                NOT
                                NULL,
                                evento
                                TEXT
                                NOT
                                NULL
                            )
                            """)
        self.conn.commit()

    def enviar_notificacao_windows(self, titulo, mensagem):
        """ Dispara um alerta nativo no canto da tela do Windows """
        try:
            notification.notify(
                title=titulo,
                message=mensagem,
                app_name="Monitor de Rede",
                app_icon=None,  # Você pode passar o caminho de um arquivo .ico se quiser
                timeout=7       # O alerta some sozinho após 7 segundos
            )
        except Exception as e:
            print(f"Falha ao emitir notificação do Windows: {e}")

    def registrar_log(self, ip, evento):
        data_hora = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.cursor.execute("INSERT INTO logs (data_hora, host_ip, evento) VALUES (?, ?, ?)", (data_hora, ip, evento))
        self.conn.commit()

        # --- TROCA AQUI: Agora avisa o Windows em vez do Telegram ---
        # Separamos o evento para criar um título curto e uma mensagem clara
        titulo_alerta = "🚨 Alerta de Segurança" if "⚠️" in evento or "❌" in evento else "ℹ️ Monitor de Rede"
        self.enviar_notificacao_windows(titulo_alerta, f"IP: {ip}\n{evento}")

        if hasattr(self, "txt_logs"):
            self.atualizar_tabela_logs()

    def criar_interface(self):
        self.abas = ctk.CTkTabview(self)
        self.abas.pack(fill="both", expand=True, padx=10, pady=10)



        self.tab_monitor = self.abas.add("Monitoramento de Dispositivos")
        self.tab_logs = self.abas.add("Logs de Auditoria")

        # ==========================================
        # INTERFACE: ABA DE MONITORAMENTO
        # ==========================================
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

        ctk.CTkLabel(self.frame_filtro, text="Filtrar por Setor:", font=ctk.CTkFont(weight="bold")).pack(side="left",
                                                                                                         padx=5)
        self.combo_filtro = ctk.CTkComboBox(self.frame_filtro, values=["Todos"], command=self.filtrar_setores_action)
        self.combo_filtro.pack(side="left", padx=5)

        # --- Cabeçalho da Tabela (Dividido em Portas Comuns vs Críticas) ---
        self.frame_header = ctk.CTkFrame(self.tab_monitor, fg_color="transparent")
        self.frame_header.pack(padx=25, fill="x", pady=(10, 0))

        colunas = [
            ("Dispositivo / IP", 0, 180),
            ("Setor", 1, 100),
            ("Status", 2, 100),
            ("Latência", 3, 100),
            ("Perda", 4, 80),
            ("Endereço MAC", 5, 160),
            ("Portas Comuns", 6, 140),  # Nova divisão aqui
            ("Portas Críticas", 7, 140),  # Nova divisão aqui
            ("Ações", 8, 150)
        ]

        for texto, col, largura in colunas:
            lbl = ctk.CTkLabel(self.frame_header, text=texto, font=ctk.CTkFont(weight="bold"), width=largura,
                               anchor="w")
            lbl.grid(row=0, column=col, padx=5, sticky="w")

        self.frame_lista = ctk.CTkScrollableFrame(self.tab_monitor)
        self.frame_lista.pack(pady=5, padx=10, fill="both", expand=True)

        # ==========================================
        # INTERFACE: ABA DE LOGS DE AUDITORIA
        # ==========================================
        self.frame_botoes_log = ctk.CTkFrame(self.tab_logs, fg_color="transparent")
        self.frame_botoes_log.pack(fill="x", padx=10, pady=5)

        self.btn_atualizar_log = ctk.CTkButton(self.frame_botoes_log, text="Atualizar Logs",
                                               command=self.atualizar_tabela_logs)
        self.btn_atualizar_log.pack(side="left", padx=5)

        self.btn_limpar_log = ctk.CTkButton(self.frame_botoes_log, text="Limpar Histórico", fg_color="#e74c3c",
                                            hover_color="#c0392b", command=self.limpar_logs_banco)
        self.btn_limpar_log.pack(side="right", padx=5)

        self.txt_logs = ctk.CTkTextbox(self.tab_logs, font=ctk.CTkFont(family="Courier", size=12))
        self.txt_logs.pack(fill="both", expand=True, padx=10, pady=10)

    def carregar_hosts_salvos(self):
        self.cursor.execute("SELECT id, nome, ip, setor FROM computadores")
        for id_db, nome, ip, setor in self.cursor.fetchall():
            self.adicionar_host_na_tela(id_db, nome, ip, setor)
        self.atualizar_lista_filtros_combobox()

    def cadastrar_host_ui(self):
        nome = self.entry_nome.get().strip()
        ip = self.entry_ip.get().strip()
        setor = self.entry_setor.get().strip()

        if not setor: setor = "Geral"

        if nome and ip:
            try:
                self.cursor.execute("INSERT INTO computadores (nome, ip, setor) VALUES (?, ?, ?)", (nome, ip, setor))
                self.conn.commit()
                id_db = self.cursor.lastrowid

                self.adicionar_host_na_tela(id_db, nome, ip, setor)
                self.registrar_log(ip, f"Novo computador cadastrado no setor [{setor}]: {nome}")
                self.atualizar_lista_filtros_combobox()

                self.entry_nome.delete(0, tk.END)
                self.entry_ip.delete(0, tk.END)
                self.entry_setor.delete(0, tk.END)
            except sqlite3.IntegrityError:
                messagebox.showerror("Erro", "Este endereço IP já está cadastrado!")

    def adicionar_host_na_tela(self, id_db, nome, ip, setor):
        row_frame = ctk.CTkFrame(self.frame_lista)

        if self.setor_atual_filtro == "Todos" or self.setor_atual_filtro == setor:
            row_frame.pack(pady=3, fill="x")
        else:
            row_frame.pack_forget()

        # Coluna 0: Nome/IP
        lbl_nome = ctk.CTkLabel(row_frame, text=f"{nome}\n({ip})", justify="left", font=ctk.CTkFont(size=13), width=180,
                                anchor="w")
        lbl_nome.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        # Coluna 1: Setor
        lbl_setor_visual = ctk.CTkLabel(row_frame, text=setor, font=ctk.CTkFont(size=12), width=100, anchor="w")
        lbl_setor_visual.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # Coluna 2: Status Conectividade
        lbl_status = ctk.CTkLabel(row_frame, text="● Aguardando", text_color="grey", font=ctk.CTkFont(weight="bold"),
                                  width=100, anchor="w")
        lbl_status.grid(row=0, column=2, padx=5, pady=5, sticky="w")

        # Coluna 3: Latência
        lbl_ms = ctk.CTkLabel(row_frame, text="---", font=ctk.CTkFont(size=12), width=100, anchor="w")
        lbl_ms.grid(row=0, column=3, padx=5, pady=5, sticky="w")

        # Coluna 4: Perda
        lbl_perda = ctk.CTkLabel(row_frame, text="0%", font=ctk.CTkFont(size=12), width=80, anchor="w")
        lbl_perda.grid(row=0, column=4, padx=5, pady=5, sticky="w")

        # Coluna 5: MAC
        lbl_mac = ctk.CTkLabel(row_frame, text="Buscando...", font=ctk.CTkFont(size=12), width=160, anchor="w")
        lbl_mac.grid(row=0, column=5, padx=5, pady=5, sticky="w")

        # Coluna 6: Portas Comuns
        lbl_portas_comuns = ctk.CTkLabel(row_frame, text="Escaneando...", font=ctk.CTkFont(size=12), width=140,
                                         anchor="w")
        lbl_portas_comuns.grid(row=0, column=6, padx=5, pady=5, sticky="w")

        # Coluna 7: Portas Críticas
        lbl_portas_criticas = ctk.CTkLabel(row_frame, text="Escaneando...", font=ctk.CTkFont(size=12, weight="bold"),
                                           width=140, anchor="w")
        lbl_portas_criticas.grid(row=0, column=7, padx=5, pady=5, sticky="w")

        # Coluna 8: Ações
        frame_acoes = ctk.CTkFrame(row_frame, fg_color="transparent")
        frame_acoes.grid(row=0, column=8, padx=5, pady=5, sticky="w")

        host_data = {
            "id": id_db, "nome": nome, "ip": ip, "setor": setor, "mac_resolvido": False,
            "status_anterior": "DESCONHECIDO", "portas_perigosas_alertadas": set(),
            "ultimo_scan_portas": 0,
            "label_nome": lbl_nome, "label_setor": lbl_setor_visual, "label_status": lbl_status,
            "label_ms": lbl_ms, "label_perda": lbl_perda, "label_mac": lbl_mac,
            "label_portas_comuns": lbl_portas_comuns, "label_portas_criticas": lbl_portas_criticas,
            "frame_linha": row_frame, "ativo": True
        }

        btn_editar = ctk.CTkButton(frame_acoes, text="Editar", width=60, fg_color="#3498db", hover_color="#2980b9",
                                   command=lambda: self.abrir_janela_edicao(host_data))
        btn_editar.pack(side="left", padx=2)

        btn_excluir = ctk.CTkButton(frame_acoes, text="Excluir", width=60, fg_color="#e74c3c", hover_color="#c0392b",
                                    command=lambda: self.excluir_host(host_data))
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
                try:
                    self.cursor.execute("UPDATE computadores SET nome = ?, ip = ?, setor = ? WHERE id = ?",
                                        (novo_nome, novo_ip, novo_setor, host_data["id"]))
                    self.conn.commit()

                    if novo_ip != host_data["ip"]:
                        host_data["mac_resolvido"] = False
                        host_data["portas_perigosas_alertadas"].clear()
                        host_data["label_mac"].configure(text="Buscando...")

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

        ctk.CTkButton(janela_edit, text="Salvar", fg_color="#2ecc71", hover_color="#27ae60",
                      command=salvar_alteracoes).pack(pady=15)

    def excluir_host(self, host_data):
        if messagebox.askyesno("Confirmar Exclusão", f"Tem certeza que deseja excluir '{host_data['nome']}'?"):
            self.cursor.execute("DELETE FROM computadores WHERE id = ?", (host_data["id"],))
            self.conn.commit()
            host_data["ativo"] = False
            self.registrar_log(host_data["ip"], f"Host removido do monitoramento: {host_data['nome']}")
            host_data["frame_linha"].destroy()
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
        self.cursor.execute("SELECT data_hora, host_ip, evento FROM logs ORDER BY id DESC LIMIT 200")
        historico = self.cursor.fetchall()

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
        if messagebox.askyesno("Limpar Histórico",
                               "Deseja apagar permanentemente todos os logs de auditoria do banco de dados?"):
            self.cursor.execute("DELETE FROM logs")
            self.conn.commit()
            self.atualizar_tabela_logs()

    def obter_mac(self, ip):
        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=1.5, verbose=False)
            for snd, rcv in ans:
                return rcv.sprintf(r"%Ether.src%").upper()
        except:
            pass
        return "Não encontrado"

    def escanear_portas(self, ip, host_data):
        portas_para_testar = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]
        comuns_abertas = []
        criticas_abertas = []

        for porta in portas_para_testar:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.05)
                    if s.connect_ex((ip, porta)) == 0:
                        if porta in PORTAS_PERIGOSAS:
                            criticas_abertas.append(porta)
                            if porta not in host_data["portas_perigosas_alertadas"]:
                                host_data["portas_perigosas_alertadas"].add(porta)
                                self.registrar_log(ip,
                                                   f"⚠️ ALERTA: Porta crítica {porta} exposta na rede por {host_data['nome']}")
                        else:
                            comuns_abertas.append(porta)
            except:
                pass

        texto_comuns = ", ".join(map(str, comuns_abertas)) if comuns_abertas else "Nenhuma"
        texto_criticas = ", ".join(map(str, criticas_abertas)) if criticas_abertas else "Nenhuma"

        return texto_comuns, texto_criticas

    def atualizar_pings_loop(self):
        while self.rodando:
            for host in list(self.hosts):
                if host is None or not isinstance(host, dict): continue
                if not host.get("ativo", False): continue

                ip = host["ip"]

                if not host["mac_resolvido"]:
                    mac = self.obter_mac(ip)
                    if host["ativo"]: host["label_mac"].configure(text=mac)
                    if mac != "Não encontrado": host["mac_resolvido"] = True

                pings_sucesso = 0
                soma_ms = 0
                total_testes = 4

                for _ in range(total_testes):
                    if not host["ativo"]: break
                    resposta = ping(ip, timeout=0.2)
                    if resposta is not None and resposta is not False:
                        pings_sucesso += 1
                        soma_ms += resposta

                if not host["ativo"]: continue

                perda = int(((total_testes - pings_sucesso) / total_testes) * 100)
                host["label_perda"].configure(text=f"{perda}%", text_color="#e74c3c" if perda > 0 else "white")

                if pings_sucesso > 0:
                    ms_medio = int((soma_ms / pings_sucesso) * 1000)
                    host["label_status"].configure(text="● ONLINE", text_color="#2ecc71")
                    host["label_ms"].configure(text=f"{ms_medio} ms")

                    # --- INÍCIO DA TRAVA DE TEMPO PARA O SCAN DE PORTAS ---
                    tempo_atual = time.time()
                    INTERVALO_SCAN = 600  # Tempo em segundos (600s = 10 minutos)

                    if tempo_atual - host.get("ultimo_scan_portas", 0) > INTERVALO_SCAN:
                        # Só faz o scan pesado se o tempo necessário já tiver passado
                        portas_comuns, portas_criticas = self.escanear_portas(ip, host)

                        if host["ativo"]:
                            # Atualiza a coluna comum com cor padrão
                            host["label_portas_comuns"].configure(
                                text=portas_comuns,
                                text_color=ctk.ThemeManager.theme["CTkLabel"]["text_color"]
                            )

                            # Atualiza a coluna crítica: se houver portas, joga VERMELHO, se não, cor padrão
                            if portas_criticas != "Nenhuma":
                                host["label_portas_criticas"].configure(text=portas_criticas, text_color="#e74c3c")
                            else:
                                host["label_portas_criticas"].configure(
                                    text=portas_criticas,
                                    text_color=ctk.ThemeManager.theme["CTkLabel"]["text_color"]
                                )

                        # Registra o timestamp de quando este scan aconteceu para reiniciar a contagem
                        host["ultimo_scan_portas"] = tempo_atual
                    # --- FIM DA TRAVA DE TEMPO ---

                    if host["status_anterior"] == "OFFLINE":
                        self.registrar_log(ip, f"Host reestabelecido: {host['nome']} está de volta online.")
                    host["status_anterior"] = "ONLINE"
                else:
                    host["label_status"].configure(text="● OFFLINE", text_color="#e74c3c")
                    host["label_ms"].configure(text="---")
                    host["label_portas_comuns"].configure(text="---", text_color="grey")
                    host["label_portas_criticas"].configure(text="---", text_color="grey")

                    if host["status_anterior"] == "ONLINE":
                        self.registrar_log(ip, f"❌ ALERTA: {host['nome']} caiu ou parou de responder aos pings.")
                    host["status_anterior"] = "OFFLINE"

                time.sleep(5)

    def monitorar_recursos_locais(self):
        # 1. Captura uso de CPU e RAM
        uso_cpu = psutil.cpu_percent(interval=1)
        uso_ram = psutil.virtual_memory().percent

        # 2. Captura espaço do disco C:
        uso_disco = psutil.disk_usage('C:').percent

        # 3. Exemplo de checagem: Se o disco passar de 90%, avisa no Windows
        if uso_disco > 90:
            self.enviar_notificacao_windows(
                "⚠️ Pouco Espaço em Disco",
                f"O disco C: atingiu {uso_disco}% da capacidade!"
            )

        return uso_cpu, uso_ram, uso_disco

    def on_closing(self):
        self.rodando = False
        self.conn.close()
        self.destroy()


if __name__ == "__main__":
    app = NetworkMonitorApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()