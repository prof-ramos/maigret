import streamlit as st
import asyncio
import json
import os
import pandas as pd
from datetime import datetime
import time
import io
import sys
import subprocess
import tempfile
import glob
from pathlib import Path
import re
import string
import logging
from typing import Dict, Any, Optional, Union, List, Tuple

# Configurar logging básico
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

# Configuração da página
st.set_page_config(
    page_title="Maigret OSINT - Ferramenta de Investigação",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/prof-ramos/maigret',
        'Report a bug': 'https://github.com/prof-ramos/maigret/issues',
        'About': '''
        ## 🕵️ Maigret OSINT Interface

        Interface web segura para investigação OSINT usando Maigret.

        ### Desenvolvido com:
        - Streamlit
        - Python 3.11+
        - Maigret OSINT Tool

        ### Segurança:
        - Validação robusta de entrada
        - Proteção contra injeção de comandos
        - Ambiente isolado
        - Logging estruturado
        '''
    }
)

# CSS personalizado para design responsivo
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
        padding: 1rem;
        background: linear-gradient(90deg, #f0f2f6, #ffffff);
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .feature-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        margin: 1rem 0;
        border-left: 4px solid #1f77b4;
    }
    
    .success-box {
        background: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    
    .error-box {
        background: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    
    .warning-box {
        background: #fff3cd;
        border: 1px solid #ffeaa7;
        color: #856404;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    
    .stButton > button {
        background: linear-gradient(90deg, #1f77b4, #0066cc);
        color: white;
        border: none;
        padding: 0.5rem 2rem;
        border-radius: 5px;
        font-weight: bold;
        transition: all 0.3s;
    }
    
    .stButton > button:hover {
        background: linear-gradient(90deg, #0066cc, #004499);
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
    
    @media (max-width: 768px) {
        .main-header {
            font-size: 2rem;
        }
        .feature-card {
            margin: 0.5rem 0;
            padding: 1rem;
        }
    }
</style>
""", unsafe_allow_html=True)

def init_session_state():
    """Inicializa o estado da sessão"""
    if 'search_history' not in st.session_state:
        st.session_state.search_history = []
    if 'current_results' not in st.session_state:
        st.session_state.current_results = None
    if 'search_in_progress' not in st.session_state:
        st.session_state.search_in_progress = False

def validate_username_secure(username: str) -> str:
    """
    Validação robusta de username com sanitização completa
    
    Args:
        username (str): Username a ser validado
        
    Returns:
        str: Username sanitizado e validado
        
    Raises:
        ValueError: Se username for inválido ou inseguro
    """
    
    # 1. Verificações básicas
    if not isinstance(username, str):
        raise ValueError("Username deve ser uma string")
    
    if not username or not username.strip():
        raise ValueError("Username não pode estar vazio")
    
    username = username.strip()
    
    # 2. Verificar comprimento
    if not (3 <= len(username) <= 50):
        raise ValueError("Username deve ter entre 3 e 50 caracteres")
    
    # 3. Caracteres permitidos (alfanumérico + alguns símbolos seguros)
    allowed_chars = set(string.ascii_letters + string.digits + '._-')
    if not set(username).issubset(allowed_chars):
        invalid_chars = set(username) - allowed_chars
        raise ValueError(f"Caracteres não permitidos: {', '.join(invalid_chars)}")
    
    # 4. Verificar padrões perigosos
    dangerous_patterns = [
        # Command injection
        '&&', '||', ';', '|', '`', '$', '!',
        # Path traversal  
        '..', '/.', '\\.',
        # Reserved words
        'rm ', 'sudo', 'chmod', 'chown', 'passwd',
        # SQL injection
        "'", '"', '--', '/*', '*/',
        # Script injection
        '<script', '</script', 'javascript:', 'data:',
    ]
    
    username_lower = username.lower()
    for pattern in dangerous_patterns:
        if pattern in username_lower:
            raise ValueError(f"Padrão proibido detectado: {pattern}")
    
    # 5. Verificar se não começa/termina com pontos ou hífens
    if username.startswith(('.', '-')) or username.endswith(('.', '-')):
        raise ValueError("Username não pode começar/terminar com . ou -")
    
    # 6. Verificar sequências repetitivas suspeitas (apenas extremamente longas)
    if any(char * 10 in username for char in string.ascii_letters + string.digits):
        raise ValueError("Sequências repetitivas suspeitas detectadas")
    
    return username

def validate_and_display_username(username: str) -> Tuple[bool, str, str]:
    """
    Valida username e retorna resultado para exibição no Streamlit
    
    Returns:
        tuple: (is_valid, clean_username, error_message)
    """
    try:
        clean_username = validate_username_secure(username)
        return True, clean_username, ""
    except ValueError as e:
        return False, "", str(e)

# Manter função antiga para compatibilidade, mas usando a nova validação
def validate_username(username: str) -> Tuple[bool, str]:
    """Função de compatibilidade - DEPRECATED: Use validate_username_secure"""
    try:
        validate_username_secure(username)
        return True, "✅ Nome de usuário válido"
    except ValueError as e:
        return False, f"❌ {str(e)}"

def run_maigret_secure(
    username: str,
    max_sites: int = 500,
    timeout_sec: int = 30,
    enable_recursion: bool = True,
    id_type: str = "username",
    tags: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Execução segura do Maigret com sanitização completa
    
    Args:
        username: Username validado e sanitizado
        max_sites: Máximo de sites a verificar
        timeout_sec: Timeout em segundos
        enable_recursion: Habilitar busca recursiva
        id_type: Tipo de ID a buscar
        tags: Lista de tags para filtrar sites
        
    Returns:
        Dict com resultado da execução
        
    Raises:
        ValueError: Se parâmetros forem inválidos
        subprocess.TimeoutExpired: Se timeout for atingido
    """
    
    # 1. Validação de entrada
    username = validate_username_secure(username)
    
    # 2. Validar parâmetros numéricos
    if not (1 <= max_sites <= 3000):
        raise ValueError("max_sites deve estar entre 1 e 3000")
    
    if not (5 <= timeout_sec <= 300):  # Entre 5 segundos e 5 minutos
        raise ValueError("Timeout deve estar entre 5 e 300 segundos")
    
    # 3. Validar id_type
    valid_id_types = {"username", "yandex_public_id", "gaia_id", "vk_id"}
    if id_type not in valid_id_types:
        raise ValueError(f"id_type inválido. Use: {', '.join(valid_id_types)}")
    
    # 4. Validar tags
    if tags:
        valid_tag_pattern = re.compile(r'^[a-zA-Z0-9_-]+$')
        for tag in tags:
            if not valid_tag_pattern.match(tag):
                raise ValueError(f"Tag inválida: {tag}")
    
    try:
        # 5. Criar diretório temporário seguro
        with tempfile.TemporaryDirectory() as temp_dir:
            # 6. Construir comando como lista (SEGURO)
            cmd = [
                "maigret",
                username,
                "--folderoutput", temp_dir,
                "--timeout", str(timeout_sec),
                "--top-sites", str(max_sites),
                "--json", "simple",
                "--no-progressbar"
            ]
            
            # 7. Adicionar argumentos opcionais de forma segura
            if not enable_recursion:
                cmd.append("--no-recursion")
                
            if id_type != "username":
                cmd.extend(["--id-type", id_type])
                
            if tags:
                cmd.extend(["--tags", ",".join(tags)])
            
            # 8. Configurar ambiente seguro
            env = {
                "PATH": "/usr/local/bin:/usr/bin:/bin",  # PATH limitado
                "LANG": "C.UTF-8",
                "HOME": "/tmp"  # Home temporário
            }
            
            # 9. Log da execução (sem dados sensíveis)
            logging.info(f"Executando Maigret para username com {len(username)} caracteres")
            
            # 10. Execução segura (SEM shell=True)
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec + 60,  # Buffer de segurança
                check=False,
                env=env,
                cwd="/tmp"  # Working directory seguro
            )
            
            # 11. Processar resultado
            execution_result = {
                "success": process.returncode == 0,
                "returncode": process.returncode,
                "stdout": process.stdout[:10000] if process.stdout else "",  # Limitar tamanho
                "stderr": process.stderr[:5000] if process.stderr else "",   # Limitar tamanho
                "username": username,
                "timestamp": int(time.time()),
                "timeout_used": timeout_sec,
                "processed_results": []
            }
            
            if process.returncode != 0:
                execution_result["error"] = f"Erro ao executar Maigret: {process.stderr}"
                return execution_result
            
            # 12. Procurar e processar arquivo JSON de resultados
            try:
                json_files = glob.glob(os.path.join(temp_dir, "**", "*.json"), recursive=True)
                
                if not json_files:
                    execution_result["error"] = "Nenhum arquivo de resultado encontrado"
                    return execution_result
                
                # Ler o primeiro arquivo JSON encontrado
                with open(json_files[0], 'r', encoding='utf-8') as f:
                    results_data = json.load(f)
                
                # Processar resultados para o formato da interface
                processed_results = []
                
                if isinstance(results_data, dict):
                    for site_name, site_data in results_data.items():
                        if isinstance(site_data, dict):
                            status = "encontrado" if site_data.get("status", {}).get("status") == "CLAIMED" else "não encontrado"
                            url = site_data.get("url_user", "")
                            
                            # Calcular confiabilidade baseada nos dados do Maigret
                            confidence = 0
                            if status == "encontrado":
                                confidence = 85  # Base para sites encontrados
                                
                                # Aumentar confiabilidade se há dados extras
                                if site_data.get("ids"):
                                    confidence += 10
                                if site_data.get("is_parsed"):
                                    confidence += 5
                            
                            processed_results.append({
                                "nome": site_name,
                                "url": url,
                                "status": status,
                                "confiabilidade": min(confidence, 100),
                                "dados_extras": site_data.get("ids", {}),
                                "parseado": site_data.get("is_parsed", False)
                            })
                
                execution_result["processed_results"] = processed_results
                execution_result["sites_found"] = len([r for r in processed_results if r["status"] == "encontrado"])
                
            except (json.JSONDecodeError, IOError) as e:
                logging.warning(f"Erro ao carregar resultado: {e}")
                execution_result["error"] = f"Erro ao processar resultados: {str(e)}"
            
            return execution_result
            
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout na execução do Maigret ({timeout_sec}s)")
        raise
    except Exception as e:
        logging.error(f"Erro inesperado: {e}")
        raise

# Função wrapper para manter compatibilidade com código existente
def run_real_maigret_search(
    username: str,
    max_sites: int = 500,
    timeout: int = 30,
    enable_recursion: bool = True,
    id_type: str = "username",
    tags: Optional[str] = None
) -> Union[List[Dict], Dict[str, str]]:
    """
    Wrapper para manter compatibilidade com interface existente
    DEPRECATED: Use run_maigret_secure diretamente
    """
    try:
        # Converter tags string para lista
        tags_list = None
        if tags:
            tags_list = [tag.strip() for tag in tags.split(",") if tag.strip()]
        
        result = run_maigret_secure(
            username=username,
            max_sites=max_sites,
            timeout_sec=timeout,
            enable_recursion=enable_recursion,
            id_type=id_type,
            tags=tags_list
        )
        
        # Retornar no formato antigo para compatibilidade
        if result.get("success"):
            return result["processed_results"]
        else:
            return {"error": result.get("error", "Erro desconhecido")}
            
    except Exception as e:
        return {"error": f"Erro na execução: {str(e)}"}

def get_maigret_stats():
    """Obtém estatísticas da base de dados do Maigret"""
    try:
        process = subprocess.run(
            ["maigret", "--stats"],
            capture_output=True,
            text=True,
            timeout=30
        )
        return process.stdout
    except Exception as e:
        return f"Erro ao obter estatísticas: {str(e)}"

def get_available_tags():
    """Obtém tags disponíveis dos sites"""
    try:
        stats = get_maigret_stats()
        # Extrair tags das estatísticas (implementação simplificada)
        common_tags = ["social", "photo", "music", "business", "gaming", "dating", "forum", "blog", "coding"]
        return common_tags
    except Exception:
        return ["social", "photo", "music", "business", "gaming"]

def check_maigret_installation():
    """Verifica se o Maigret está instalado e funcionando"""
    try:
        result = subprocess.run(
            ["maigret", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            return True, version
        else:
            return False, f"Erro ao executar Maigret: {result.stderr}"
    except FileNotFoundError:
        return False, "Maigret não encontrado. Instale com: pip install maigret"
    except subprocess.TimeoutExpired:
        return False, "Timeout ao verificar Maigret"
    except Exception as e:
        return False, f"Erro inesperado: {str(e)}"

def main():
    init_session_state()

    # Verificar instalação do Maigret
    maigret_ok, maigret_message = check_maigret_installation()
    if not maigret_ok:
        st.error(f"❌ Problema com Maigret: {maigret_message}")
        st.warning("💡 Instale o Maigret antes de usar a aplicação")
        st.stop()

    # Cabeçalho principal
    st.markdown('<div class="main-header">🕵️ Maigret OSINT - Investigação de Perfis</div>', unsafe_allow_html=True)
    
    # Sidebar com informações
    with st.sidebar:
        st.markdown("### 📋 Sobre o Maigret")

        # Status do Maigret
        if maigret_ok:
            st.success(f"✅ Maigret instalado: {maigret_message}")
        else:
            st.error(f"❌ Problema: {maigret_message}")

        st.markdown("""
        O Maigret é uma poderosa ferramenta OSINT (Open Source Intelligence)
        que permite coletar informações sobre uma pessoa através do nome de usuário
        em mais de 3.000 sites diferentes.
        """)
        
        st.markdown("### ⚠️ Uso Ético")
        st.warning("""
        Esta ferramenta deve ser usada apenas para:
        - Investigações legítimas
        - Pesquisa acadêmica
        - Verificação de identidade própria
        - Segurança cibernética
        
        NÃO use para stalking ou assédio!
        """)
        
        st.markdown("### 📊 Estatísticas da Sessão")
        st.metric("Buscas Realizadas", len(st.session_state.search_history))
        if st.session_state.current_results:
            perfis_encontrados = len([r for r in st.session_state.current_results if r.get("status") == "encontrado"])
            st.metric("Perfis Encontrados", perfis_encontrados)
    
    # Área principal - Tabs para diferentes funcionalidades
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["🔍 Busca Principal", "📊 Análise de Resultados", "📈 Relatórios", "📈 Estatísticas Maigret", "⚙️ Configurações"])
    
    with tab1:
        st.markdown('<div class="feature-card">', unsafe_allow_html=True)
        st.markdown("## 🔍 Buscar Perfis por Nome de Usuário")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            username = st.text_input(
                "Digite o nome de usuário para investigar:",
                placeholder="Ex: usuario123",
                help="Insira o nome de usuário que deseja investigar em redes sociais"
            )
        
        with col2:
            max_sites = st.selectbox(
                "Máximo de sites:",
                [10, 25, 50, 100, 500],
                index=2,
                help="Número máximo de sites para verificar"
            )
        
        # Opções avançadas em expander
        with st.expander("⚙️ Configurações Avançadas"):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                id_type = st.selectbox(
                    "Tipo de ID:",
                    ["username", "yandex_public_id", "gaia_id", "vk_id", "ok_id", "steam_id"],
                    help="Tipo de identificador para busca"
                )
                
            with col2:
                enable_recursion = st.checkbox(
                    "Busca recursiva",
                    value=True,
                    help="Buscar por novos usernames encontrados nas páginas"
                )
                
            with col3:
                timeout = st.slider(
                    "Timeout (segundos):",
                    5, 60, 30,
                    help="Tempo limite por site"
                )
            
            # Tags de sites
            available_tags = get_available_tags()
            selected_tags = st.multiselect(
                "Filtrar por tags de sites:",
                available_tags,
                help="Selecione tipos de sites para focar a busca"
            )
            
            tags_string = ",".join(selected_tags) if selected_tags else None
        
        # Validação em tempo real melhorada
        if username:
            is_valid, clean_username, error_msg = validate_and_display_username(username)
            if is_valid:
                st.markdown(f'<div class="success-box">✅ Username válido: `{clean_username}`</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="error-box">❌ {error_msg}</div>', unsafe_allow_html=True)
        
        # Botão de busca
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("🚀 Iniciar Investigação", disabled=st.session_state.search_in_progress):
                if username:
                    # Validação robusta antes da execução
                    is_valid, clean_username, error_msg = validate_and_display_username(username)
                    
                    if is_valid:
                        # Container para resultados
                        result_container = st.container()
                        
                        with result_container:
                            # Progress bar
                            progress_bar = st.progress(0)
                            status_text = st.empty()
                            
                            try:
                                st.session_state.search_in_progress = True
                                
                                status_text.text("🔍 Iniciando busca...")
                                progress_bar.progress(10)
                                
                                status_text.text("⚙️ Validando configurações...")
                                progress_bar.progress(20)
                                
                                # Executar busca segura
                                status_text.text("🚀 Executando Maigret...")
                                progress_bar.progress(30)
                                
                                # Converter tags para lista
                                tags_list = None
                                if selected_tags:
                                    tags_list = selected_tags
                                
                                # Usar função segura
                                result = run_maigret_secure(
                                    username=clean_username,
                                    max_sites=max_sites,
                                    timeout_sec=timeout,
                                    enable_recursion=enable_recursion,
                                    id_type=id_type,
                                    tags=tags_list
                                )
                                
                                progress_bar.progress(80)
                                status_text.text("📊 Processando resultados...")
                                
                                # Verificar sucesso
                                if result['success']:
                                    progress_bar.progress(100)
                                    status_text.text("✅ Busca concluída com sucesso!")
                                    
                                    # Processar e salvar resultados
                                    processed_results = result['processed_results']
                                    
                                    st.session_state.current_results = processed_results
                                    st.session_state.search_history.append({
                                        "username": clean_username,
                                        "timestamp": datetime.now(),
                                        "sites_verificados": len(processed_results),
                                        "perfis_encontrados": result.get('sites_found', 0)
                                    })
                                    
                                    # Exibir métricas
                                    col1, col2, col3 = st.columns(3)
                                    with col1:
                                        st.metric("Sites Verificados", len(processed_results))
                                    with col2:
                                        st.metric("Perfis Encontrados", result.get('sites_found', 0))
                                    with col3:
                                        success_rate = (result.get('sites_found', 0) / len(processed_results) * 100) if processed_results else 0
                                        st.metric("Taxa de Sucesso", f"{success_rate:.1f}%")
                                    
                                    st.success("✅ Busca realizada com sucesso! Verifique os resultados na aba 'Análise de Resultados'.")
                                    
                                else:
                                    # Erro na execução
                                    st.error("❌ Erro na execução do Maigret")
                                    
                                    with st.expander("🔍 Detalhes do erro"):
                                        st.text(f"Código de retorno: {result['returncode']}")
                                        if result.get('stderr'):
                                            st.text("Erro:")
                                            st.code(result['stderr'])
                                        if result.get('stdout'):
                                            st.text("Saída:")
                                            st.code(result['stdout'])
                                
                            except ValueError as e:
                                st.error(f"❌ Erro de validação: {str(e)}")
                                logging.error(f"Validation error: {e}")
                                
                            except subprocess.TimeoutExpired:
                                st.error("❌ Timeout: A busca demorou mais que o esperado")
                                st.info("💡 Tente reduzir o timeout ou número de sites")
                                logging.error("Search timeout expired")
                                
                            except Exception as e:
                                st.error("❌ Erro inesperado na busca")
                                logging.error(f"Unexpected error: {e}")
                                
                                # Só mostrar detalhes técnicos em modo debug
                                if st.session_state.get('debug_mode', False):
                                    with st.expander("🔧 Detalhes técnicos (modo debug)"):
                                        st.exception(e)
                            
                            finally:
                                # Limpar estado
                                st.session_state.search_in_progress = False
                                progress_bar.empty()
                                status_text.empty()
                    else:
                        st.markdown(f'<div class="error-box">❌ {error_msg}</div>', unsafe_allow_html=True)
                else:
                    st.markdown('<div class="error-box">❌ Por favor, insira um nome de usuário</div>', unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Mostrar resultados da última busca
        if st.session_state.current_results:
            st.markdown('<div class="feature-card">', unsafe_allow_html=True)
            st.markdown("## 📋 Resultados da Busca")
            
            perfis_encontrados = [r for r in st.session_state.current_results if r.get("status") == "encontrado"]
            perfis_nao_encontrados = [r for r in st.session_state.current_results if r.get("status") == "não encontrado"]
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Sites Verificados", len(st.session_state.current_results))
            with col2:
                st.metric("Perfis Encontrados", len(perfis_encontrados))
            with col3:
                taxa_sucesso = (len(perfis_encontrados) / len(st.session_state.current_results)) * 100
                st.metric("Taxa de Sucesso", f"{taxa_sucesso:.1f}%")
            
            # Tabela de resultados encontrados
            if perfis_encontrados:
                st.markdown("### ✅ Perfis Encontrados")
                df_encontrados = pd.DataFrame(perfis_encontrados)
                
                # Formatação da tabela
                df_display = df_encontrados[['nome', 'url', 'confiabilidade']].copy()
                df_display.columns = ['Plataforma', 'URL', 'Confiabilidade (%)']
                
                st.dataframe(
                    df_display,
                    width='stretch',
                    column_config={
                        "URL": st.column_config.LinkColumn("URL"),
                        "Confiabilidade (%)": st.column_config.ProgressColumn(
                            "Confiabilidade (%)",
                            min_value=0,
                            max_value=100,
                        ),
                    }
                )
            
            st.markdown('</div>', unsafe_allow_html=True)
    
    with tab2:
        st.markdown('<div class="feature-card">', unsafe_allow_html=True)
        st.markdown("## 📊 Análise Detalhada dos Resultados")
        
        if st.session_state.current_results:
            # Gráfico de distribuição
            col1, col2 = st.columns(2)
            
            with col1:
                # Gráfico de pizza - Status dos perfis
                perfis_encontrados = len([r for r in st.session_state.current_results if r.get("status") == "encontrado"])
                perfis_nao_encontrados = len([r for r in st.session_state.current_results if r.get("status") == "não encontrado"])
                
                df_status = pd.DataFrame({
                    'Status': ['Encontrados', 'Não Encontrados'],
                    'Quantidade': [perfis_encontrados, perfis_nao_encontrados]
                })
                
                st.markdown("### 📈 Distribuição de Resultados")
                st.bar_chart(df_status.set_index('Status'))
            
            with col2:
                # Análise de confiabilidade
                confiabilidades = [r.get("confiabilidade", 0) for r in st.session_state.current_results if r.get("status") == "encontrado"]
                confiabilidades_num = [c for c in confiabilidades if isinstance(c, (int, float))]
                if confiabilidades_num:
                    st.markdown("### 🎯 Análise de Confiabilidade")
                    st.metric("Confiabilidade Média", f"{sum(confiabilidades_num)/len(confiabilidades_num):.1f}%")
                    st.metric("Maior Confiabilidade", f"{max(confiabilidades_num)}%")
                    st.metric("Menor Confiabilidade", f"{min(confiabilidades_num)}%")
            
            # Listagem detalhada com filtros
            st.markdown("### 🔍 Filtros e Detalhes")
            
            col1, col2 = st.columns(2)
            with col1:
                status_filter = st.selectbox("Filtrar por status:", ["Todos", "Encontrados", "Não Encontrados"])
            with col2:
                confiabilidade_min = st.slider("Confiabilidade mínima:", 0, 100, 0)
            
            # Aplicar filtros
            filtered_results = st.session_state.current_results.copy()
            
            if status_filter == "Encontrados":
                filtered_results = [r for r in filtered_results if r.get("status") == "encontrado"]
            elif status_filter == "Não Encontrados":
                filtered_results = [r for r in filtered_results if r.get("status") == "não encontrado"]
            
            filtered_results = [r for r in filtered_results if isinstance(r.get("confiabilidade", 0), (int, float)) and r.get("confiabilidade", 0) >= confiabilidade_min]
            
            if filtered_results:
                df_filtered = pd.DataFrame(filtered_results)
                st.dataframe(df_filtered, width='stretch')
            else:
                st.info("Nenhum resultado encontrado com os filtros aplicados.")
        
        else:
            st.info("Execute uma busca primeiro para ver a análise dos resultados.")
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    with tab3:
        st.markdown('<div class="feature-card">', unsafe_allow_html=True)
        st.markdown("## 📈 Relatórios e Exportação")
        
        if st.session_state.current_results:
            # Seção de relatórios principais
            st.markdown("### 📋 Relatórios Rápidos")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("📄 Gerar Relatório JSON"):
                    report_data = {
                        "timestamp": datetime.now().isoformat(),
                        "total_sites": len(st.session_state.current_results),
                        "profiles_found": len([r for r in st.session_state.current_results if r.get("status") == "encontrado"]),
                        "results": st.session_state.current_results
                    }
                    
                    json_str = json.dumps(report_data, indent=2, ensure_ascii=False)
                    st.download_button(
                        label="⬇️ Baixar Relatório JSON",
                        data=json_str,
                        file_name=f"maigret_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
            
            with col2:
                if st.button("📊 Gerar Relatório CSV"):
                    df = pd.DataFrame(st.session_state.current_results)
                    csv = df.to_csv(index=False)
                    st.download_button(
                        label="⬇️ Baixar Relatório CSV",
                        data=csv,
                        file_name=f"maigret_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
            
            with col3:
                if st.button("📈 Relatório Detalhado"):
                    # Gerar relatório mais detalhado
                    perfis_encontrados = [r for r in st.session_state.current_results if r.get("status") == "encontrado"]
                    
                    html_content = f"""
                    <html>
                    <head>
                        <title>Relatório Maigret OSINT</title>
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 20px; }}
                            .header {{ background: #1f77b4; color: white; padding: 20px; text-align: center; }}
                            .summary {{ background: #f8f9fa; padding: 15px; margin: 20px 0; }}
                            .profile {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; }}
                            .found {{ border-left: 4px solid #28a745; }}
                            .not-found {{ border-left: 4px solid #dc3545; }}
                        </style>
                    </head>
                    <body>
                        <div class="header">
                            <h1>🕵️ Relatório Maigret OSINT</h1>
                            <p>Investigação de perfis online</p>
                        </div>
                        
                        <div class="summary">
                            <h2>📊 Resumo da Investigação</h2>
                            <p><strong>Data:</strong> {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
                            <p><strong>Total de sites verificados:</strong> {len(st.session_state.current_results)}</p>
                            <p><strong>Perfis encontrados:</strong> {len(perfis_encontrados)}</p>
                            <p><strong>Taxa de sucesso:</strong> {(len(perfis_encontrados)/len(st.session_state.current_results)*100):.1f}%</p>
                        </div>
                        
                        <h2>✅ Perfis Encontrados</h2>
                    """
                    
                    for perfil in perfis_encontrados:
                        html_content += f"""
                        <div class="profile found">
                            <h3>{perfil.get('nome', 'N/A')}</h3>
                            <p><strong>URL:</strong> <a href="{perfil.get('url', '#')}" target="_blank">{perfil.get('url', 'N/A')}</a></p>
                            <p><strong>Confiabilidade:</strong> {perfil.get('confiabilidade', 0)}%</p>
                        </div>
                        """
                    
                    html_content += "</body></html>"
                    
                    st.download_button(
                        label="⬇️ Baixar Relatório HTML",
                        data=html_content,
                        file_name=f"maigret_detailed_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                        mime="text/html"
                    )
            
            # Histórico de buscas
            st.markdown("### 📚 Histórico de Buscas")
            if st.session_state.search_history:
                df_history = pd.DataFrame(st.session_state.search_history)
                st.dataframe(df_history, width='stretch')
            else:
                st.info("Nenhuma busca realizada ainda.")
        
        else:
            st.info("Execute uma busca primeiro para gerar relatórios.")
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    with tab4:
        st.markdown('<div class="feature-card">', unsafe_allow_html=True)
        st.markdown("## 📈 Estatísticas do Banco de Dados Maigret")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📊 Obter Estatísticas da Base de Dados"):
                with st.spinner("Carregando estatísticas..."):
                    stats = get_maigret_stats()
                    st.text_area("Estatísticas do Maigret:", stats, height=400)
        
        with col2:
            st.markdown("### 🏷️ Tags Disponíveis")
            tags = get_available_tags()
            for tag in tags:
                st.button(f"#{tag}", key=f"tag_{tag}", help=f"Sites relacionados a {tag}")
        
        # Informações sobre a base de dados
        st.markdown("### 📊 Sobre a Base de Dados")
        st.info("""
        O Maigret possui uma base de dados com mais de 3.000 sites diferentes, incluindo:
        
        - **Redes Sociais**: Facebook, Instagram, Twitter, LinkedIn, etc.
        - **Plataformas de Gaming**: Steam, Xbox Live, PlayStation, etc.
        - **Sites de Código**: GitHub, GitLab, SourceForge, etc.
        - **Fóruns e Comunidades**: Reddit, Stack Overflow, etc.
        - **Sites de Música**: Spotify, SoundCloud, Bandcamp, etc.
        - **Plataformas de Vídeo**: YouTube, Vimeo, TikTok, etc.
        - **Sites de Dating**: Tinder, Badoo, Match, etc.
        - **Plataformas Profissionais**: AngelList, Behance, Dribbble, etc.
        """)
        
        # Funcionalidades avançadas
        st.markdown("### 🔧 Funcionalidades Avançadas Disponíveis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            ✅ **Implementadas na Interface:**
            - Busca por username
            - Busca recursiva 
            - Filtros por tags
            - Diferentes tipos de ID
            - Relatórios JSON/CSV/HTML
            - Configuração de timeout
            - Análise de confiabilidade
            """)
        
        with col2:
            st.markdown("""
            📋 **Funcionalidades do Maigret Original:**
            - Parsing de páginas web
            - Geração de relatórios PDF/XMind
            - Suporte a proxy Tor/I2P
            - Verificação de domínios
            - Busca em sites I2P/Tor
            - Auto-verificação de sites
            - Detecção de captcha/censura
            """)
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    with tab5:
        st.markdown('<div class="feature-card">', unsafe_allow_html=True)
        st.markdown("## ⚙️ Configurações e Preferências")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🔧 Configurações de Busca")
            timeout = st.slider("Timeout por site (segundos):", 5, 30, 10)
            max_concurrent = st.slider("Conexões simultâneas:", 10, 100, 50)
            use_tor = st.checkbox("Usar proxy Tor (mais lento, mais anônimo)")
            
        with col2:
            st.markdown("### 🎨 Preferências de Interface")
            show_progress = st.checkbox("Mostrar barra de progresso detalhada", value=True)
            auto_refresh = st.checkbox("Atualização automática de resultados")
            sound_alerts = st.checkbox("Alertas sonoros")
        
        st.markdown("### 🗑️ Gerenciamento de Dados")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🗑️ Limpar Histórico de Buscas"):
                st.session_state.search_history = []
                st.success("Histórico limpo com sucesso!")
        
        with col2:
            if st.button("🔄 Resetar Todas as Configurações"):
                # Reset session state
                for key in list(st.session_state.keys()):
                    del st.session_state[key]
                st.success("Configurações resetadas!")
                st.rerun()
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666; padding: 1rem;">
        <p>🕵️ Maigret OSINT Tool - Interface Streamlit em Português Brasileiro</p>
        <p>Desenvolvido com ❤️ usando Streamlit | Versão: 1.0.0</p>
        <p><small>⚠️ Use com responsabilidade e respeite a privacidade dos outros</small></p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()