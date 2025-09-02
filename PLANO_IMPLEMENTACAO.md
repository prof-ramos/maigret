# 🚀 PLANO DE IMPLEMENTAÇÃO - CORREÇÕES DE SEGURANÇA

**Projeto**: Maigret OSINT Interface  
**Data**: 02 de Setembro de 2025  
**Objetivo**: Resolver vulnerabilidades críticas e implementar testes

---

## 🎯 VISÃO GERAL DO PLANO

### Fases de Implementação
```
FASE 1: SEGURANÇA CRÍTICA (P0)    │ 1-3 dias  │ 🔴 OBRIGATÓRIO
FASE 2: TESTES E QUALIDADE (P1)   │ 1-2 semanas │ 🟡 ESSENCIAL  
FASE 3: MELHORIAS AVANÇADAS (P2)  │ 2-4 semanas │ 🟢 RECOMENDADO
```

### Cronograma Geral
```
Semana 1: ████████░░ 80% - Correções críticas
Semana 2: ██████████ 100% - Testes básicos  
Semana 3: ████████░░ 80% - Cobertura avançada
Semana 4: ██████████ 100% - Finalização
```

---

## 🔴 FASE 1: CORREÇÕES CRÍTICAS (P0)

### Objetivo: Eliminar vulnerabilidades de segurança críticas
**Prazo**: 1-3 dias  
**Esforço**: 20 horas  
**Status**: ⚠️ **OBRIGATÓRIO ANTES DE PRODUÇÃO**

---

### 📋 TAREFA 1.1: Validação Segura de Entrada

**Tempo**: 8 horas  
**Arquivo**: `app.py` (linhas 150-165)  
**Prioridade**: 🔴 CRÍTICA

#### Situação Atual (VULNERÁVEL)
```python
def validate_username(username):
    if len(username) < 3:
        return False
    return True  # ❌ Muito permissivo
```

#### Implementação Necessária
```python
import re
import string

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
    
    # 6. Verificar sequências repetitivas suspeitas
    if any(char * 4 in username for char in string.ascii_letters + string.digits):
        raise ValueError("Sequências repetitivas não permitidas")
    
    return username

# Função helper para uso em Streamlit
def validate_and_display_username(username: str) -> tuple[bool, str, str]:
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
```

#### Checklist de Implementação
- [ ] Substituir função `validate_username()` antiga
- [ ] Adicionar imports necessários (`re`, `string`)
- [ ] Implementar validação robusta
- [ ] Adicionar testes unitários
- [ ] Atualizar chamadas na interface Streamlit
- [ ] Documentar mudanças

---

### 📋 TAREFA 1.2: Correção de Subprocess Seguro

**Tempo**: 8 horas  
**Arquivo**: `app.py` (linhas 200-250)  
**Prioridade**: 🔴 CRÍTICA

#### Situação Atual (VULNERÁVEL)
```python
def run_real_maigret_search(username, ...):
    cmd = f"maigret {username} --json simple"  # ❌ String interpolation
    result = subprocess.run(cmd, shell=True)    # ❌ shell=True vulnerável
```

#### Implementação Necessária
```python
import subprocess
import json
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

def run_maigret_secure(
    username: str,
    output_format: str = "json",
    timeout_sec: int = 30,
    max_connections: int = 50,
    tags: Optional[List[str]] = None,
    proxy: Optional[str] = None,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Execução segura do Maigret com sanitização completa
    
    Args:
        username: Username validado e sanitizado
        output_format: Formato de saída (json, csv, etc.)
        timeout_sec: Timeout em segundos
        max_connections: Máximo de conexões simultâneas
        tags: Lista de tags para filtrar sites
        proxy: URL do proxy (opcional)
        verbose: Modo verboso
        
    Returns:
        Dict com resultado da execução
        
    Raises:
        ValueError: Se parâmetros forem inválidos
        subprocess.TimeoutExpired: Se timeout for atingido
        subprocess.CalledProcessError: Se comando falhar
    """
    
    # 1. Validação de entrada
    username = validate_username_secure(username)
    
    # 2. Validar formato de saída
    valid_formats = {"json", "csv", "txt", "html"}
    if output_format not in valid_formats:
        raise ValueError(f"Formato inválido. Use: {', '.join(valid_formats)}")
    
    # 3. Validar timeout
    if not (5 <= timeout_sec <= 300):  # Entre 5 segundos e 5 minutos
        raise ValueError("Timeout deve estar entre 5 e 300 segundos")
    
    # 4. Validar max_connections
    if not (1 <= max_connections <= 100):
        raise ValueError("max_connections deve estar entre 1 e 100")
    
    # 5. Construir comando como lista (SEGURO)
    cmd = [
        "maigret",
        username,
        "--json", "simple" if output_format == "json" else "ndjson",
        "--timeout", str(timeout_sec),
        "--connections", str(max_connections)
    ]
    
    # 6. Adicionar argumentos opcionais de forma segura
    if tags:
        # Validar tags
        valid_tag_pattern = re.compile(r'^[a-zA-Z0-9_-]+$')
        for tag in tags:
            if not valid_tag_pattern.match(tag):
                raise ValueError(f"Tag inválida: {tag}")
        cmd.extend(["--tags", ",".join(tags)])
    
    if proxy:
        # Validar formato do proxy
        proxy_pattern = re.compile(r'^https?://[a-zA-Z0-9.-]+:\d+/?$')
        if not proxy_pattern.match(proxy):
            raise ValueError("Formato de proxy inválido")
        cmd.extend(["--proxy", proxy])
    
    if verbose:
        cmd.append("--verbose")
    
    # 7. Configurar ambiente seguro
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",  # PATH limitado
        "LANG": "C.UTF-8",
        "HOME": "/tmp"  # Home temporário
    }
    
    # 8. Criar diretório temporário para saída
    output_dir = Path("/tmp/maigret_output")
    output_dir.mkdir(exist_ok=True, mode=0o700)  # Apenas owner
    
    output_file = output_dir / f"{username}_{int(time.time())}.json"
    cmd.extend(["--output", str(output_file)])
    
    # 9. Log da execução (sem dados sensíveis)
    logging.info(f"Executando Maigret para username com {len(username)} caracteres")
    logging.debug(f"Comando: {' '.join(cmd[:3])} [argumentos omitidos]")
    
    try:
        # 10. Execução segura (SEM shell=True)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec + 10,  # Buffer de segurança
            check=False,
            env=env,
            cwd="/tmp"  # Working directory seguro
        )
        
        # 11. Processar resultado
        execution_result = {
            "success": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout[:10000],  # Limitar tamanho
            "stderr": result.stderr[:5000],   # Limitar tamanho
            "username": username,
            "timestamp": int(time.time()),
            "timeout_used": timeout_sec,
            "output_file": str(output_file) if output_file.exists() else None
        }
        
        # 12. Carregar dados se arquivo foi criado
        if output_file.exists():
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    maigret_data = json.load(f)
                    execution_result["data"] = maigret_data
                    execution_result["sites_found"] = len(maigret_data.get("sites", {}))
            except (json.JSONDecodeError, IOError) as e:
                logging.warning(f"Erro ao carregar resultado: {e}")
                execution_result["data"] = None
                execution_result["parse_error"] = str(e)
            finally:
                # Limpar arquivo temporário
                output_file.unlink(missing_ok=True)
        
        return execution_result
        
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout na execução do Maigret ({timeout_sec}s)")
        raise
    except subprocess.CalledProcessError as e:
        logging.error(f"Erro na execução do Maigret: {e}")
        raise
    except Exception as e:
        logging.error(f"Erro inesperado: {e}")
        raise
    finally:
        # Limpeza final
        if output_file.exists():
            output_file.unlink(missing_ok=True)

# Função wrapper para compatibilidade com código existente
def run_real_maigret_search(
    username: str,
    timeout_sec: int = 30,
    max_connections: int = 50,
    tags: Optional[str] = None,
    proxy: Optional[str] = None,
    verbosity: bool = False
) -> Dict[str, Any]:
    """
    Wrapper para manter compatibilidade com interface existente
    """
    # Converter tags string para lista
    tags_list = None
    if tags:
        tags_list = [tag.strip() for tag in tags.split(",") if tag.strip()]
    
    return run_maigret_secure(
        username=username,
        timeout_sec=timeout_sec,
        max_connections=max_connections,
        tags=tags_list,
        proxy=proxy,
        verbose=verbosity
    )
```

#### Checklist de Implementação
- [ ] Substituir função `run_real_maigret_search()` vulnerável
- [ ] Implementar validação de todos os parâmetros
- [ ] Usar lista de argumentos em vez de string
- [ ] Adicionar ambiente seguro para execução
- [ ] Implementar logging de segurança
- [ ] Adicionar limpeza de arquivos temporários
- [ ] Testar execução com vários cenários

---

### 📋 TAREFA 1.3: Tratamento de Erros Robusto

**Tempo**: 4 horas  
**Arquivo**: `app.py` (interface Streamlit)  
**Prioridade**: 🔴 CRÍTICA

#### Implementação Necessária
```python
import streamlit as st
import logging
from typing import Optional

def handle_search_with_error_management():
    """
    Gerencia busca com tratamento robusto de erros
    """
    
    if 'search_in_progress' not in st.session_state:
        st.session_state.search_in_progress = False
    
    # Interface de busca
    col1, col2 = st.columns([3, 1])
    
    with col1:
        username_input = st.text_input(
            "Username para investigação:",
            placeholder="Digite o username...",
            help="Use apenas letras, números, pontos, hífens e underscores"
        )
    
    with col2:
        search_button = st.button(
            "🔍 Buscar",
            disabled=st.session_state.search_in_progress,
            type="primary"
        )
    
    # Validação em tempo real
    if username_input:
        is_valid, clean_username, error_msg = validate_and_display_username(username_input)
        
        if not is_valid:
            st.error(f"❌ {error_msg}")
            return
        else:
            st.success(f"✅ Username válido: `{clean_username}`")
    
    # Execução da busca
    if search_button and username_input:
        
        # Validar novamente antes da execução
        is_valid, clean_username, error_msg = validate_and_display_username(username_input)
        
        if not is_valid:
            st.error(f"❌ Erro de validação: {error_msg}")
            return
        
        # Configurar busca
        st.session_state.search_in_progress = True
        
        # Container para resultados
        result_container = st.container()
        
        with result_container:
            # Progress bar
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            try:
                status_text.text("🔍 Iniciando busca...")
                progress_bar.progress(10)
                
                # Obter configurações
                config = get_search_configuration()
                
                status_text.text("⚙️ Validando configurações...")
                progress_bar.progress(20)
                
                # Executar busca segura
                status_text.text("🚀 Executando Maigret...")
                progress_bar.progress(30)
                
                result = run_maigret_secure(
                    username=clean_username,
                    timeout_sec=config['timeout'],
                    max_connections=config['max_connections'],
                    tags=config.get('tags'),
                    proxy=config.get('proxy'),
                    verbose=config.get('verbose', False)
                )
                
                progress_bar.progress(80)
                status_text.text("📊 Processando resultados...")
                
                # Verificar sucesso
                if result['success']:
                    progress_bar.progress(100)
                    status_text.text("✅ Busca concluída com sucesso!")
                    
                    # Exibir resultados
                    display_search_results(result, clean_username)
                    
                    # Salvar no histórico
                    save_to_history(clean_username, result)
                    
                else:
                    # Erro na execução
                    st.error("❌ Erro na execução do Maigret")
                    
                    with st.expander("🔍 Detalhes do erro"):
                        st.text(f"Código de retorno: {result['returncode']}")
                        if result['stderr']:
                            st.text("Erro:")
                            st.code(result['stderr'])
                        if result['stdout']:
                            st.text("Saída:")
                            st.code(result['stdout'])
                
            except ValueError as e:
                st.error(f"❌ Erro de validação: {str(e)}")
                logging.error(f"Validation error: {e}")
                
            except subprocess.TimeoutExpired:
                st.error("❌ Timeout: A busca demorou mais que o esperado")
                st.info("💡 Tente reduzir o timeout ou número de conexões")
                logging.error("Search timeout expired")
                
            except subprocess.CalledProcessError as e:
                st.error(f"❌ Erro na execução: {str(e)}")
                logging.error(f"Subprocess error: {e}")
                
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

def get_search_configuration() -> dict:
    """Obter configurações de busca da sidebar"""
    with st.sidebar:
        st.subheader("⚙️ Configurações de Busca")
        
        config = {
            'timeout': st.slider("Timeout (segundos):", 5, 300, 30),
            'max_connections': st.slider("Conexões máximas:", 1, 100, 50),
            'verbose': st.checkbox("Modo verboso", False)
        }
        
        # Tags opcionais
        available_tags = get_available_tags()
        selected_tags = st.multiselect("Filtrar por categorias:", available_tags)
        if selected_tags:
            config['tags'] = selected_tags
        
        # Proxy opcional
        proxy_url = st.text_input("Proxy (opcional):", placeholder="http://proxy:8080")
        if proxy_url:
            config['proxy'] = proxy_url
        
        return config
```

#### Checklist de Implementação
- [ ] Implementar validação em tempo real
- [ ] Adicionar tratamento de exceções específicas
- [ ] Criar feedback visual de progresso
- [ ] Implementar logging de erros
- [ ] Adicionar modo debug para troubleshooting
- [ ] Testar cenários de erro

---

## 🟡 FASE 2: TESTES E QUALIDADE (P1)

### Objetivo: Implementar cobertura de testes e melhorar qualidade
**Prazo**: 1-2 semanas  
**Esforço**: 32 horas  
**Status**: 🟡 **ESSENCIAL PARA PRODUÇÃO**

---

### 📋 TAREFA 2.1: Configuração de Ambiente de Testes

**Tempo**: 4 horas  
**Prioridade**: 🟡 ALTA

#### Estrutura de Diretórios
```bash
mkdir -p tests/{unit,integration,security,fixtures}
```

#### Arquivos de Configuração

**requirements-test.txt**
```txt
pytest==8.2.2
pytest-cov==5.0.0
pytest-mock==3.14.0
pytest-timeout==2.3.1
pytest-xdist==3.6.0
pytest-html==4.1.1
pytest-json-report==1.5.0
streamlit[testing]==1.49.1
```

**pytest.ini**
```ini
[tool:pytest]
testpaths = tests
python_files = test_*.py *_test.py
python_classes = Test*
python_functions = test_*
addopts = 
    --verbose
    --tb=short
    --cov=app
    --cov-report=html
    --cov-report=term-missing
    --cov-report=xml
    --html=reports/pytest_report.html
    --json-report --json-report-file=reports/pytest_report.json
    --timeout=300
markers =
    unit: Unit tests
    integration: Integration tests  
    security: Security tests
    slow: Slow running tests
filterwarnings =
    ignore::DeprecationWarning
    ignore::PendingDeprecationWarning
```

**conftest.py**
```python
import pytest
import tempfile
import os
from unittest.mock import Mock, patch
import streamlit as st

@pytest.fixture
def temp_dir():
    """Diretório temporário para testes"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir

@pytest.fixture
def mock_subprocess():
    """Mock do subprocess para testes seguros"""
    with patch('subprocess.run') as mock_run:
        # Configurar retorno padrão bem-sucedido
        mock_run.return_value = Mock(
            returncode=0,
            stdout='{"sites": {"github": {"status": "found"}}}',
            stderr='',
        )
        yield mock_run

@pytest.fixture
def streamlit_app():
    """Configurar ambiente Streamlit para testes"""
    # Limpar session state
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    
    yield st

@pytest.fixture
def sample_maigret_result():
    """Resultado exemplo do Maigret para testes"""
    return {
        "sites": {
            "GitHub": {
                "status": "found",
                "url": "https://github.com/testuser",
                "response_time": 0.5
            },
            "Twitter": {
                "status": "not_found",
                "url": "https://twitter.com/testuser"
            }
        },
        "search_stats": {
            "total_sites": 2,
            "found": 1,
            "not_found": 1
        }
    }
```

#### Checklist de Configuração
- [ ] Criar estrutura de diretórios
- [ ] Instalar dependências de teste
- [ ] Configurar pytest.ini
- [ ] Criar fixtures básicas
- [ ] Configurar coverage reporting
- [ ] Testar configuração básica

---

### 📋 TAREFA 2.2: Testes Unitários de Segurança

**Tempo**: 8 horas  
**Arquivo**: `tests/unit/test_security.py`  
**Prioridade**: 🟡 ALTA

```python
import pytest
import subprocess
from unittest.mock import patch, Mock
from app import validate_username_secure, run_maigret_secure

class TestUsernameValidation:
    """Testes de validação de username"""
    
    def test_valid_usernames(self):
        """Testa usernames válidos"""
        valid_usernames = [
            "user123",
            "test.user",
            "my-username",
            "user_name",
            "abc",
            "a" * 50  # Máximo permitido
        ]
        
        for username in valid_usernames:
            result = validate_username_secure(username)
            assert result == username
    
    def test_invalid_lengths(self):
        """Testa usernames com tamanho inválido"""
        # Muito curtos
        with pytest.raises(ValueError, match="entre 3 e 50 caracteres"):
            validate_username_secure("ab")
        
        # Muito longos  
        with pytest.raises(ValueError, match="entre 3 e 50 caracteres"):
            validate_username_secure("a" * 51)
    
    def test_invalid_characters(self):
        """Testa caracteres não permitidos"""
        invalid_usernames = [
            "user@domain.com",  # @
            "user space",       # espaço
            "user/path",        # /
            "user\\path",       # \\
            "user#hash",        # #
            "user%percent",     # %
            "user&and",         # &
        ]
        
        for username in invalid_usernames:
            with pytest.raises(ValueError, match="Caracteres não permitidos"):
                validate_username_secure(username)
    
    def test_command_injection_attempts(self):
        """Testa tentativas de injeção de comandos"""
        injection_attempts = [
            "user; ls -la",
            "user && cat /etc/passwd",
            "user || echo 'hacked'",
            "user | grep secret",
            "user `whoami`",
            "user $(id)",
            "user; rm -rf /",
            "user && sudo su",
            "user; chmod 777 *"
        ]
        
        for malicious in injection_attempts:
            with pytest.raises(ValueError):
                validate_username_secure(malicious)
    
    def test_path_traversal_attempts(self):
        """Testa tentativas de path traversal"""
        traversal_attempts = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "user/../admin",
            "user/./secret",
            "user\\.\\config"
        ]
        
        for attempt in traversal_attempts:
            with pytest.raises(ValueError):
                validate_username_secure(attempt)
    
    def test_sql_injection_attempts(self):
        """Testa tentativas de SQL injection"""
        sql_injection_attempts = [
            "user'; DROP TABLE users;--",
            'user" OR 1=1--',
            "user/* comment */",
            "user*/"
        ]
        
        for attempt in sql_injection_attempts:
            with pytest.raises(ValueError):
                validate_username_secure(attempt)
    
    def test_script_injection_attempts(self):
        """Testa tentativas de script injection"""
        script_attempts = [
            "<script>alert('xss')</script>",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>"
        ]
        
        for attempt in script_attempts:
            with pytest.raises(ValueError):
                validate_username_secure(attempt)
    
    @pytest.mark.parametrize("invalid_input", [
        None,           # None
        123,            # int
        [],             # list
        {},             # dict
        "",             # string vazia
        "   ",          # só espaços
    ])
    def test_invalid_input_types(self, invalid_input):
        """Testa tipos de entrada inválidos"""
        with pytest.raises(ValueError):
            validate_username_secure(invalid_input)

class TestSecureSubprocess:
    """Testes de execução segura de subprocess"""
    
    @patch('subprocess.run')
    def test_secure_command_construction(self, mock_run):
        """Testa construção segura do comando"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='{"sites": {}}',
            stderr=''
        )
        
        result = run_maigret_secure("testuser")
        
        # Verificar que comando foi construído como lista
        args, kwargs = mock_run.call_args
        cmd = args[0]
        
        assert isinstance(cmd, list)
        assert cmd[0] == "maigret"
        assert cmd[1] == "testuser"
        assert "--json" in cmd
        assert "shell" not in kwargs or kwargs["shell"] is False
    
    @patch('subprocess.run')
    def test_parameter_sanitization(self, mock_run):
        """Testa sanitização de parâmetros"""
        mock_run.return_value = Mock(returncode=0, stdout='{}', stderr='')
        
        # Parâmetros válidos
        result = run_maigret_secure(
            username="testuser",
            timeout_sec=60,
            max_connections=25,
            tags=["social", "professional"]
        )
        
        # Verificar sanitização
        args, kwargs = mock_run.call_args
        cmd = args[0]
        
        assert "60" in cmd  # timeout sanitizado
        assert "25" in cmd  # connections sanitizado
        assert "social,professional" in cmd  # tags sanitizadas
    
    def test_invalid_parameters(self):
        """Testa parâmetros inválidos"""
        # Timeout inválido
        with pytest.raises(ValueError, match="Timeout deve estar"):
            run_maigret_secure("testuser", timeout_sec=1000)
        
        # Connections inválidas
        with pytest.raises(ValueError, match="max_connections deve estar"):
            run_maigret_secure("testuser", max_connections=500)
        
        # Formato inválido
        with pytest.raises(ValueError, match="Formato inválido"):
            run_maigret_secure("testuser", output_format="invalid")
    
    @patch('subprocess.run')
    def test_environment_security(self, mock_run):
        """Testa configuração segura do ambiente"""
        mock_run.return_value = Mock(returncode=0, stdout='{}', stderr='')
        
        run_maigret_secure("testuser")
        
        args, kwargs = mock_run.call_args
        
        # Verificar ambiente limitado
        assert 'env' in kwargs
        env = kwargs['env']
        assert env['PATH'] == "/usr/local/bin:/usr/bin:/bin"
        assert env['HOME'] == "/tmp"
        
        # Verificar working directory seguro
        assert kwargs.get('cwd') == "/tmp"
    
    @patch('subprocess.run')
    def test_timeout_handling(self, mock_run):
        """Testa tratamento de timeout"""
        # Simular timeout
        mock_run.side_effect = subprocess.TimeoutExpired("maigret", 30)
        
        with pytest.raises(subprocess.TimeoutExpired):
            run_maigret_secure("testuser", timeout_sec=30)
    
    @patch('subprocess.run')
    def test_error_handling(self, mock_run):
        """Testa tratamento de erros"""
        # Simular erro de comando
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Command failed"
        )
        
        result = run_maigret_secure("testuser")
        
        assert result['success'] is False
        assert result['returncode'] == 1
        assert "Command failed" in result['stderr']

class TestDataSanitization:
    """Testes de sanitização de dados"""
    
    def test_output_size_limits(self):
        """Testa limites de tamanho de saída"""
        # Mock com saída muito grande
        large_output = "x" * 20000
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout=large_output,
                stderr="error" * 2000
            )
            
            result = run_maigret_secure("testuser")
            
            # Verificar truncamento
            assert len(result['stdout']) <= 10000
            assert len(result['stderr']) <= 5000
    
    def test_sensitive_data_filtering(self):
        """Testa filtragem de dados sensíveis"""
        # Mock com dados potencialmente sensíveis
        sensitive_output = """
        {
            "sites": {
                "test": {
                    "password": "secret123",
                    "api_key": "abc123def456"
                }
            }
        }
        """
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout=sensitive_output,
                stderr=""
            )
            
            result = run_maigret_secure("testuser")
            
            # Dados sensíveis não devem estar no log
            assert "secret123" not in str(result)
            assert "abc123def456" not in str(result)
```

#### Checklist de Testes de Segurança
- [ ] Implementar testes de validação
- [ ] Testar tentativas de command injection
- [ ] Testar path traversal
- [ ] Testar SQL injection
- [ ] Testar script injection
- [ ] Testar sanitização de parâmetros
- [ ] Testar configuração de ambiente seguro
- [ ] Executar todos os testes

---

### 📋 TAREFA 2.3: Testes de Integração

**Tempo**: 12 horas  
**Arquivo**: `tests/integration/test_streamlit_integration.py`  
**Prioridade**: 🟡 ALTA

```python
import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest
from unittest.mock import patch, Mock
import json
import tempfile
import os

class TestStreamlitIntegration:
    """Testes de integração da interface Streamlit"""
    
    def test_app_loads_successfully(self):
        """Testa se a aplicação carrega sem erros"""
        at = AppTest.from_file("app.py")
        at.run()
        
        # Verificar que não há exceções
        assert not at.exception
        
        # Verificar elementos básicos da UI
        assert len(at.title) > 0  # Tem título
        assert len(at.text_input) > 0  # Tem input de texto
        assert len(at.button) > 0  # Tem botões
    
    def test_tab_navigation(self):
        """Testa navegação entre abas"""
        at = AppTest.from_file("app.py")
        at.run()
        
        # Verificar que todas as abas estão presentes
        expected_tabs = ["🔍 Busca", "📊 Análise", "📋 Relatórios", "📈 Estatísticas", "⚙️ Configurações"]
        
        # Streamlit cria elementos tab, verificar se existem
        assert len(at.tabs) > 0
    
    @patch('app.run_maigret_secure')
    def test_search_functionality(self, mock_maigret):
        """Testa funcionalidade de busca completa"""
        # Configurar mock
        mock_maigret.return_value = {
            "success": True,
            "returncode": 0,
            "data": {
                "sites": {
                    "GitHub": {"status": "found", "url": "https://github.com/testuser"}
                }
            },
            "sites_found": 1
        }
        
        at = AppTest.from_file("app.py")
        at.run()
        
        # Simular entrada de usuário
        at.text_input[0].input("testuser").run()
        
        # Clicar no botão de busca
        search_button = None
        for button in at.button:
            if "Buscar" in button.label or "🔍" in button.label:
                search_button = button
                break
        
        assert search_button is not None
        search_button.click().run()
        
        # Verificar que Maigret foi chamado
        mock_maigret.assert_called_once()
        
        # Verificar que não há exceções
        assert not at.exception
    
    @patch('app.run_maigret_secure')
    def test_error_handling_in_ui(self, mock_maigret):
        """Testa tratamento de erros na interface"""
        # Configurar mock para simular erro
        mock_maigret.side_effect = ValueError("Teste de erro")
        
        at = AppTest.from_file("app.py")
        at.run()
        
        # Simular busca com erro
        at.text_input[0].input("testuser").run()
        
        # Clicar no botão de busca
        for button in at.button:
            if "Buscar" in button.label or "🔍" in button.label:
                button.click().run()
                break
        
        # Verificar que erro foi tratado (não há exception não capturada)
        assert not at.exception
        
        # Verificar se há mensagem de erro na UI
        error_found = any("erro" in str(element).lower() for element in at.error)
        assert error_found
    
    def test_configuration_persistence(self):
        """Testa persistência de configurações"""
        at = AppTest.from_file("app.py")
        at.run()
        
        # Verificar se session_state foi inicializado
        # (Não podemos acessar diretamente, mas podemos verificar comportamento)
        
        # Aplicação deve carregar configurações padrão
        assert not at.exception
    
    @patch('app.run_maigret_secure')
    def test_result_display(self, mock_maigret):
        """Testa exibição de resultados"""
        # Mock com resultado completo
        mock_result = {
            "success": True,
            "returncode": 0,
            "data": {
                "sites": {
                    "GitHub": {
                        "status": "found",
                        "url": "https://github.com/testuser",
                        "response_time": 0.5
                    },
                    "Twitter": {
                        "status": "not_found",
                        "url": "https://twitter.com/testuser"
                    }
                }
            },
            "sites_found": 1
        }
        
        mock_maigret.return_value = mock_result
        
        at = AppTest.from_file("app.py")
        at.run()
        
        # Executar busca
        at.text_input[0].input("testuser").run()
        
        for button in at.button:
            if "Buscar" in button.label or "🔍" in button.label:
                button.click().run()
                break
        
        # Verificar se resultados são exibidos
        assert not at.exception
        
        # Verificar se há elementos de resultado (métricas, tabelas, etc.)
        has_results = (
            len(at.metric) > 0 or 
            len(at.dataframe) > 0 or 
            len(at.table) > 0
        )
        assert has_results

class TestDataProcessing:
    """Testes de processamento de dados"""
    
    def test_result_parsing(self):
        """Testa parsing de resultados do Maigret"""
        sample_result = {
            "sites": {
                "GitHub": {
                    "status": "found",
                    "url": "https://github.com/testuser",
                    "response_time": 0.5
                },
                "Twitter": {
                    "status": "not_found",
                    "url": "https://twitter.com/testuser"
                },
                "LinkedIn": {
                    "status": "found", 
                    "url": "https://linkedin.com/in/testuser"
                }
            }
        }
        
        # Importar função de processamento da app
        from app import process_maigret_results
        
        processed = process_maigret_results(sample_result)
        
        assert processed['total_sites'] == 3
        assert processed['found_sites'] == 2
        assert processed['not_found_sites'] == 1
        assert processed['success_rate'] == pytest.approx(66.67, rel=1e-2)
    
    def test_export_functionality(self):
        """Testa funcionalidade de exportação"""
        sample_data = {
            "sites": {
                "GitHub": {"status": "found", "url": "https://github.com/testuser"}
            }
        }
        
        from app import export_to_csv, export_to_json
        
        # Testar exportação CSV
        csv_content = export_to_csv(sample_data)
        assert "GitHub" in csv_content
        assert "found" in csv_content
        
        # Testar exportação JSON
        json_content = export_to_json(sample_data)
        parsed = json.loads(json_content)
        assert "GitHub" in parsed["sites"]

class TestPerformance:
    """Testes de performance"""
    
    @pytest.mark.slow
    def test_large_result_handling(self):
        """Testa tratamento de resultados grandes"""
        # Simular resultado com muitos sites
        large_result = {
            "sites": {
                f"site_{i}": {
                    "status": "found" if i % 2 == 0 else "not_found",
                    "url": f"https://site{i}.com/testuser"
                }
                for i in range(1000)  # 1000 sites
            }
        }
        
        # Testar processamento
        from app import process_maigret_results
        
        import time
        start_time = time.time()
        processed = process_maigret_results(large_result)
        processing_time = time.time() - start_time
        
        # Verificar que processamento é eficiente (< 5 segundos)
        assert processing_time < 5.0
        
        # Verificar resultado correto
        assert processed['total_sites'] == 1000
        assert processed['found_sites'] == 500
    
    def test_memory_usage(self):
        """Testa uso de memória"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Executar operação que pode consumir memória
        at = AppTest.from_file("app.py")
        at.run()
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Verificar que aumento de memória é razoável (< 100MB)
        assert memory_increase < 100
```

#### Checklist de Testes de Integração
- [ ] Implementar testes de carregamento da app
- [ ] Testar navegação entre abas
- [ ] Testar funcionalidade de busca end-to-end
- [ ] Testar tratamento de erros na UI
- [ ] Testar exibição de resultados
- [ ] Testar exportação de dados
- [ ] Testar performance com dados grandes
- [ ] Executar suite completa de testes

---

### 📋 TAREFA 2.4: Cobertura de Testes 

**Tempo**: 8 horas  
**Prioridade**: 🟡 ALTA

#### Configuração de Coverage

**Makefile para automação**
```makefile
.PHONY: test test-unit test-integration test-security coverage report clean

# Executar todos os testes
test:
	pytest tests/ -v --cov=app --cov-report=html --cov-report=term-missing

# Executar apenas testes unitários
test-unit:
	pytest tests/unit/ -v -m "unit"

# Executar apenas testes de integração  
test-integration:
	pytest tests/integration/ -v -m "integration"

# Executar apenas testes de segurança
test-security:
	pytest tests/security/ -v -m "security"

# Executar com cobertura detalhada
coverage:
	pytest tests/ --cov=app --cov-report=html --cov-report=xml --cov-report=term-missing --cov-fail-under=60

# Gerar relatório HTML
report:
	pytest tests/ --cov=app --cov-report=html --html=reports/pytest_report.html

# Limpar arquivos temporários
clean:
	rm -rf htmlcov/
	rm -rf reports/
	rm -rf .coverage
	rm -rf .pytest_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
```

#### Script de Análise de Cobertura

**scripts/coverage_analysis.py**
```python
#!/usr/bin/env python3
"""
Script para análise detalhada de cobertura de testes
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
import sys

def analyze_coverage_xml(xml_path: str) -> dict:
    """Analisa arquivo XML de cobertura"""
    
    if not Path(xml_path).exists():
        print(f"❌ Arquivo {xml_path} não encontrado")
        return {}
    
    tree = ET.parse(xml_path)
    root = tree.getroot()
    
    coverage_data = {
        'overall': {},
        'files': {},
        'missing_lines': {}
    }
    
    # Cobertura geral
    coverage_data['overall'] = {
        'line_rate': float(root.get('line-rate', 0)) * 100,
        'branch_rate': float(root.get('branch-rate', 0)) * 100,
        'lines_covered': int(root.get('lines-covered', 0)),
        'lines_valid': int(root.get('lines-valid', 0))
    }
    
    # Cobertura por arquivo
    for package in root.findall('.//package'):
        for class_elem in package.findall('.//class'):
            filename = class_elem.get('filename')
            line_rate = float(class_elem.get('line-rate', 0)) * 100
            
            coverage_data['files'][filename] = {
                'line_rate': line_rate,
                'lines_covered': int(class_elem.get('lines-covered', 0)),
                'lines_valid': int(class_elem.get('lines-valid', 0))
            }
            
            # Linhas não cobertas
            missing_lines = []
            lines = class_elem.find('lines')
            if lines is not None:
                for line in lines.findall('line'):
                    if line.get('hits') == '0':
                        missing_lines.append(int(line.get('number')))
            
            coverage_data['missing_lines'][filename] = sorted(missing_lines)
    
    return coverage_data

def generate_coverage_report(coverage_data: dict) -> str:
    """Gera relatório de cobertura em texto"""
    
    report = []
    
    # Cabeçalho
    report.append("📊 RELATÓRIO DE COBERTURA DE TESTES")
    report.append("=" * 50)
    report.append("")
    
    # Cobertura geral
    overall = coverage_data.get('overall', {})
    line_rate = overall.get('line_rate', 0)
    
    report.append("🎯 COBERTURA GERAL")
    report.append(f"  Cobertura de Linhas: {line_rate:.1f}%")
    report.append(f"  Linhas Cobertas: {overall.get('lines_covered', 0)}")
    report.append(f"  Linhas Válidas: {overall.get('lines_valid', 0)}")
    
    # Status baseado na cobertura
    if line_rate >= 85:
        status = "✅ EXCELENTE"
    elif line_rate >= 70:
        status = "🟡 BOM"
    elif line_rate >= 50:
        status = "🟠 RAZOÁVEL"
    else:
        status = "🔴 INSUFICIENTE"
    
    report.append(f"  Status: {status}")
    report.append("")
    
    # Cobertura por arquivo
    report.append("📁 COBERTURA POR ARQUIVO")
    files = coverage_data.get('files', {})
    
    for filename, file_data in sorted(files.items(), key=lambda x: x[1]['line_rate']):
        file_rate = file_data['line_rate']
        
        if file_rate >= 80:
            status_icon = "✅"
        elif file_rate >= 60:
            status_icon = "🟡"
        elif file_rate >= 40:
            status_icon = "🟠"
        else:
            status_icon = "🔴"
        
        report.append(f"  {status_icon} {filename}: {file_rate:.1f}%")
    
    report.append("")
    
    # Linhas críticas não cobertas
    report.append("⚠️ LINHAS CRÍTICAS NÃO COBERTAS")
    missing = coverage_data.get('missing_lines', {})
    
    for filename, lines in missing.items():
        if lines:
            report.append(f"  📄 {filename}:")
            
            # Agrupar linhas consecutivas
            grouped_lines = []
            start = lines[0]
            end = lines[0]
            
            for line in lines[1:]:
                if line == end + 1:
                    end = line
                else:
                    if start == end:
                        grouped_lines.append(str(start))
                    else:
                        grouped_lines.append(f"{start}-{end}")
                    start = end = line
            
            if start == end:
                grouped_lines.append(str(start))
            else:
                grouped_lines.append(f"{start}-{end}")
            
            report.append(f"    Linhas: {', '.join(grouped_lines)}")
    
    return "\n".join(report)

def main():
    """Função principal"""
    
    # Verificar se coverage.xml existe
    coverage_xml = "coverage.xml"
    
    if not Path(coverage_xml).exists():
        print("❌ Arquivo coverage.xml não encontrado")
        print("💡 Execute: pytest --cov=app --cov-report=xml")
        sys.exit(1)
    
    # Analisar cobertura
    print("📊 Analisando cobertura de testes...")
    coverage_data = analyze_coverage_xml(coverage_xml)
    
    if not coverage_data:
        print("❌ Erro ao analisar dados de cobertura")
        sys.exit(1)
    
    # Gerar relatório
    report = generate_coverage_report(coverage_data)
    print(report)
    
    # Salvar relatório em arquivo
    report_file = Path("reports/coverage_analysis.txt")
    report_file.parent.mkdir(exist_ok=True)
    report_file.write_text(report)
    
    print(f"\n💾 Relatório salvo em: {report_file}")
    
    # Verificar se atende critério mínimo
    line_rate = coverage_data.get('overall', {}).get('line_rate', 0)
    
    if line_rate < 60:
        print(f"\n❌ Cobertura insuficiente: {line_rate:.1f}% (mínimo: 60%)")
        sys.exit(1)
    else:
        print(f"\n✅ Cobertura adequada: {line_rate:.1f}%")

if __name__ == "__main__":
    main()
```

#### Checklist de Cobertura
- [ ] Configurar relatórios de cobertura
- [ ] Implementar script de análise
- [ ] Configurar Makefile para automação
- [ ] Executar análise inicial
- [ ] Identificar linhas críticas não cobertas
- [ ] Implementar testes para aumentar cobertura
- [ ] Atingir meta de 60% de cobertura mínima

---

## 🟢 FASE 3: MELHORIAS AVANÇADAS (P2)

### Objetivo: Otimizações e ferramentas de qualidade
**Prazo**: 2-4 semanas  
**Esforço**: 24 horas  
**Status**: 🟢 **RECOMENDADO**

---

### 📋 TAREFA 3.1: Correção de Warnings LSP

**Tempo**: 4 horas  
**Prioridade**: 🟢 MÉDIA

#### Análise dos Warnings Atuais
```bash
# Executar diagnóstico LSP
python -m pylsp --help > /dev/null && echo "LSP disponível" || echo "LSP não disponível"
```

#### Correções Típicas Necessárias

**Problema: Acesso a método 'get' em string**
```python
# ❌ ANTES (linhas 383, 404, 405, etc.)
result = some_string.get('key', 'default')

# ✅ DEPOIS - Verificação de tipo
if isinstance(result, dict):
    value = result.get('key', 'default')
elif isinstance(result, str):
    value = result if 'key' in result else 'default'
else:
    value = 'default'

# ✅ AINDA MELHOR - Type hints
from typing import Union, Dict, Any

def process_data(data: Union[str, Dict[str, Any]]) -> str:
    if isinstance(data, dict):
        return data.get('key', 'default')
    return str(data)
```

#### Script de Correção Automática

**scripts/fix_lsp_warnings.py**
```python
#!/usr/bin/env python3
"""
Script para corrigir warnings LSP automaticamente
"""

import re
import ast
from pathlib import Path
from typing import List, Tuple

def find_string_get_calls(source_code: str) -> List[Tuple[int, str]]:
    """Encontra chamadas .get() em strings"""
    
    problems = []
    lines = source_code.split('\n')
    
    for i, line in enumerate(lines, 1):
        # Procurar padrões problemáticos
        if '.get(' in line:
            # Verificar se é realmente uma string
            # Isso é uma heurística simples
            if any(pattern in line for pattern in [
                "st.session_state.get(",
                "result.get(",
                "data.get(",
                "config.get("
            ]):
                problems.append((i, line.strip()))
    
    return problems

def fix_string_get_calls(source_code: str) -> str:
    """Corrige chamadas .get() problemáticas"""
    
    lines = source_code.split('\n')
    fixed_lines = []
    
    for line in lines:
        original_line = line
        
        # Padrões a corrigir
        replacements = [
            # st.session_state que pode ser string
            (
                r'st\.session_state\.get\(([^,)]+),\s*([^)]+)\)',
                r'st.session_state.get(\1, \2) if isinstance(st.session_state, dict) else \2'
            ),
            # Outros padrões comuns
            (
                r'(\w+)\.get\(([^,)]+),\s*([^)]+)\)',
                r'\1.get(\2, \3) if isinstance(\1, dict) else \3'
            )
        ]
        
        for pattern, replacement in replacements:
            if re.search(pattern, line):
                # Aplicar correção apenas se a linha não foi modificada
                if '# LSP-FIXED' not in line:
                    line = re.sub(pattern, replacement, line)
                    line += '  # LSP-FIXED'
                    break
        
        fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)

def add_type_hints(source_code: str) -> str:
    """Adiciona type hints básicos"""
    
    lines = source_code.split('\n')
    fixed_lines = []
    
    for line in lines:
        # Adicionar imports se necessário
        if line.strip() == "import streamlit as st":
            fixed_lines.append(line)
            fixed_lines.append("from typing import Dict, Any, Optional, Union  # LSP-FIXED")
            continue
        
        # Adicionar type hints a funções sem tipos
        if re.match(r'^def \w+\([^)]*\):$', line.strip()):
            # Função sem type hints
            if 'def main(' in line:
                line = line.replace('def main():', 'def main() -> None:  # LSP-FIXED')
            elif 'def validate_username(' in line:
                line = line.replace(
                    'def validate_username(username):',
                    'def validate_username(username: str) -> bool:  # LSP-FIXED'
                )
            # Adicionar outros casos conforme necessário
        
        fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)

def main():
    """Função principal"""
    
    app_file = Path("app.py")
    
    if not app_file.exists():
        print("❌ Arquivo app.py não encontrado")
        return
    
    print("🔧 Analisando warnings LSP...")
    
    # Ler código fonte
    source_code = app_file.read_text(encoding='utf-8')
    
    # Encontrar problemas
    problems = find_string_get_calls(source_code)
    
    if problems:
        print(f"📋 Encontrados {len(problems)} possíveis problemas:")
        for line_num, line_text in problems[:5]:  # Mostrar apenas os primeiros 5
            print(f"  Linha {line_num}: {line_text}")
        
        # Aplicar correções
        print("\n🔧 Aplicando correções...")
        
        fixed_code = fix_string_get_calls(source_code)
        fixed_code = add_type_hints(fixed_code)
        
        # Fazer backup
        backup_file = app_file.with_suffix('.py.backup')
        backup_file.write_text(source_code, encoding='utf-8')
        print(f"💾 Backup salvo em: {backup_file}")
        
        # Salvar código corrigido
        app_file.write_text(fixed_code, encoding='utf-8')
        print(f"✅ Correções aplicadas em: {app_file}")
        
        print("\n⚠️ IMPORTANTE: Revise as correções manualmente!")
        print("As correções automáticas podem precisar de ajustes.")
        
    else:
        print("✅ Nenhum problema encontrado!")

if __name__ == "__main__":
    main()
```

#### Checklist de Correção LSP
- [ ] Executar análise de warnings
- [ ] Aplicar correções automáticas
- [ ] Revisar correções manualmente
- [ ] Adicionar type hints
- [ ] Testar aplicação após correções
- [ ] Verificar que warnings foram resolvidos

---

### 📋 TAREFA 3.2: Atualização de Dependências

**Tempo**: 4 horas  
**Prioridade**: 🟢 MÉDIA

#### Script de Atualização Segura

**scripts/update_dependencies.py**
```python
#!/usr/bin/env python3
"""
Script para atualização segura de dependências
"""

import subprocess
import json
from pathlib import Path
import sys

def get_outdated_packages() -> dict:
    """Obter lista de pacotes desatualizados"""
    
    try:
        result = subprocess.run(
            ["pip", "list", "--outdated", "--format=json"],
            capture_output=True,
            text=True,
            check=True
        )
        
        return json.loads(result.stdout)
    
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        print(f"❌ Erro ao obter pacotes desatualizados: {e}")
        return []

def update_package_safely(package_name: str, target_version: str) -> bool:
    """Atualizar pacote com testes de segurança"""
    
    print(f"🔄 Atualizando {package_name} para {target_version}...")
    
    try:
        # 1. Fazer backup do requirements.txt
        requirements_file = Path("requirements.txt")
        if requirements_file.exists():
            backup_file = requirements_file.with_suffix('.txt.backup')
            backup_file.write_text(requirements_file.read_text())
        
        # 2. Instalar nova versão
        subprocess.run(
            ["pip", "install", f"{package_name}=={target_version}"],
            check=True,
            capture_output=True
        )
        
        # 3. Executar testes básicos
        print(f"  🧪 Testando {package_name}...")
        
        test_result = subprocess.run(
            ["python", "-c", f"import {package_name}; print(f'✅ {package_name} OK')"],
            capture_output=True,
            text=True
        )
        
        if test_result.returncode != 0:
            print(f"  ❌ Teste de importação falhou para {package_name}")
            return False
        
        # 4. Executar testes unitários se existirem
        if Path("tests").exists():
            test_result = subprocess.run(
                ["pytest", "tests/unit/", "-v", "--tb=short"],
                capture_output=True,
                text=True
            )
            
            if test_result.returncode != 0:
                print(f"  ❌ Testes unitários falharam após atualizar {package_name}")
                print(f"  Erro: {test_result.stdout}")
                return False
        
        print(f"  ✅ {package_name} atualizado com sucesso!")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"  ❌ Erro ao atualizar {package_name}: {e}")
        return False

def main():
    """Função principal"""
    
    print("📦 ATUALIZAÇÃO SEGURA DE DEPENDÊNCIAS")
    print("=" * 40)
    
    # Obter pacotes desatualizados
    outdated = get_outdated_packages()
    
    if not outdated:
        print("✅ Todos os pacotes estão atualizados!")
        return
    
    print(f"📋 Encontrados {len(outdated)} pacotes desatualizados:")
    
    # Categorizar por prioridade
    high_priority = ["networkx", "lxml"]
    medium_priority = ["beautifulsoup4", "requests", "urllib3"]
    low_priority = ["about-time"]
    
    for pkg in outdated:
        name = pkg["name"]
        current = pkg["version"]
        latest = pkg["latest_version"]
        
        if name in high_priority:
            priority = "🔴 ALTA"
        elif name in medium_priority:
            priority = "🟡 MÉDIA"
        else:
            priority = "🟢 BAIXA"
        
        print(f"  {priority} {name}: {current} → {latest}")
    
    print("\n🚀 Iniciando atualizações...")
    
    # Atualizar por prioridade
    success_count = 0
    total_count = 0
    
    for priority_list, priority_name in [
        (high_priority, "ALTA"),
        (medium_priority, "MÉDIA"),
        (low_priority, "BAIXA")
    ]:
        print(f"\n📋 Atualizando pacotes de prioridade {priority_name}:")
        
        for pkg in outdated:
            name = pkg["name"]
            
            if name in priority_list:
                total_count += 1
                
                if update_package_safely(name, pkg["latest_version"]):
                    success_count += 1
                else:
                    print(f"  ⚠️ Mantendo {name} na versão atual por segurança")
    
    # Resumo final
    print(f"\n📊 RESUMO:")
    print(f"  ✅ Atualizados: {success_count}/{total_count}")
    print(f"  📦 Total de pacotes: {len(outdated)}")
    
    if success_count == total_count:
        print("🎉 Todas as atualizações foram bem-sucedidas!")
    else:
        print("⚠️ Algumas atualizações falharam. Verifique logs acima.")
    
    # Atualizar requirements.txt
    print("\n💾 Atualizando requirements.txt...")
    
    try:
        result = subprocess.run(
            ["pip", "freeze"],
            capture_output=True,
            text=True,
            check=True
        )
        
        requirements_file = Path("requirements.txt")
        requirements_file.write_text(result.stdout)
        print("✅ requirements.txt atualizado!")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Erro ao atualizar requirements.txt: {e}")

if __name__ == "__main__":
    main()
```

#### Checklist de Atualização
- [ ] Fazer backup do ambiente atual
- [ ] Executar script de análise de dependências
- [ ] Atualizar pacotes de alta prioridade
- [ ] Executar testes após cada atualização
- [ ] Atualizar requirements.txt
- [ ] Validar funcionamento da aplicação

---

### 📋 TAREFA 3.3: Auditoria Automática de Segurança

**Tempo**: 8 horas  
**Prioridade**: 🟢 MÉDIA

#### Configuração de Ferramentas

**scripts/security_audit.py**
```python
#!/usr/bin/env python3
"""
Script para auditoria automática de segurança
"""

import subprocess
import json
import sys
from pathlib import Path
from datetime import datetime

def run_bandit_scan() -> dict:
    """Executar scan do Bandit"""
    
    print("🛡️ Executando análise Bandit...")
    
    try:
        result = subprocess.run(
            ["bandit", "-r", ".", "-f", "json", "-o", "bandit_report.json"],
            capture_output=True,
            text=True
        )
        
        # Bandit retorna código 1 mesmo quando encontra problemas
        # Verificar se arquivo foi criado
        if Path("bandit_report.json").exists():
            with open("bandit_report.json") as f:
                data = json.load(f)
            return data
        else:
            print("❌ Relatório Bandit não foi gerado")
            return {}
            
    except FileNotFoundError:
        print("❌ Bandit não encontrado. Instale com: pip install bandit")
        return {}
    except Exception as e:
        print(f"❌ Erro no Bandit: {e}")
        return {}

def run_safety_check() -> dict:
    """Executar verificação Safety"""
    
    print("🔍 Executando verificação Safety...")
    
    try:
        result = subprocess.run(
            ["safety", "check", "--json"],
            capture_output=True,
            text=True
        )
        
        if result.stdout:
            return json.loads(result.stdout)
        else:
            return {"vulnerabilities": []}
            
    except FileNotFoundError:
        print("❌ Safety não encontrado. Instale com: pip install safety")
        return {}
    except json.JSONDecodeError:
        # Safety às vezes retorna texto quando não há vulnerabilidades
        return {"vulnerabilities": []}
    except Exception as e:
        print(f"❌ Erro no Safety: {e}")
        return {}

def analyze_code_patterns() -> dict:
    """Analisar padrões inseguros no código"""
    
    print("🔍 Analisando padrões de código...")
    
    dangerous_patterns = {
        "subprocess_shell": r"subprocess\..*shell\s*=\s*True",
        "eval_usage": r"\beval\s*\(",
        "exec_usage": r"\bexec\s*\(",
        "pickle_load": r"pickle\.loads?\s*\(",
        "yaml_unsafe": r"yaml\.load\s*\(",
        "sql_string_format": r"\.format\s*\(.*\%s.*\)",
        "hardcoded_secret": r"(password|secret|key)\s*=\s*['\"][^'\"]{8,}['\"]",
    }
    
    findings = {}
    
    for pattern_name, pattern in dangerous_patterns.items():
        findings[pattern_name] = []
        
        for py_file in Path(".").rglob("*.py"):
            try:
                content = py_file.read_text(encoding='utf-8')
                lines = content.split('\n')
                
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        findings[pattern_name].append({
                            "file": str(py_file),
                            "line": i,
                            "content": line.strip()
                        })
                        
            except Exception as e:
                print(f"⚠️ Erro ao analisar {py_file}: {e}")
    
    return findings

def generate_security_report(bandit_data: dict, safety_data: dict, pattern_data: dict) -> str:
    """Gerar relatório de segurança consolidado"""
    
    report = []
    
    # Cabeçalho
    report.append("🛡️ RELATÓRIO DE AUDITORIA DE SEGURANÇA")
    report.append("=" * 50)
    report.append(f"Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    report.append("")
    
    # Resumo executivo
    bandit_issues = len(bandit_data.get("results", []))
    safety_vulns = len(safety_data.get("vulnerabilities", []))
    pattern_issues = sum(len(findings) for findings in pattern_data.values())
    
    total_issues = bandit_issues + safety_vulns + pattern_issues
    
    report.append("📊 RESUMO EXECUTIVO")
    report.append(f"  Total de Problemas: {total_issues}")
    report.append(f"  ├─ Bandit (Código): {bandit_issues}")
    report.append(f"  ├─ Safety (Dependências): {safety_vulns}")
    report.append(f"  └─ Padrões Inseguros: {pattern_issues}")
    report.append("")
    
    # Status geral
    if total_issues == 0:
        status = "✅ SEGURO"
    elif total_issues <= 5:
        status = "🟡 ATENÇÃO"
    else:
        status = "🔴 RISCOS CRÍTICOS"
    
    report.append(f"🎯 STATUS GERAL: {status}")
    report.append("")
    
    # Detalhes do Bandit
    if bandit_data.get("results"):
        report.append("🛡️ PROBLEMAS ENCONTRADOS PELO BANDIT")
        
        for issue in bandit_data["results"][:10]:  # Limitar a 10
            severity = issue.get("issue_severity", "UNKNOWN")
            confidence = issue.get("issue_confidence", "UNKNOWN")
            
            severity_icon = {
                "HIGH": "🔴",
                "MEDIUM": "🟡", 
                "LOW": "🟢"
            }.get(severity, "⚪")
            
            report.append(f"  {severity_icon} {issue.get('test_name', 'Unknown')}")
            report.append(f"    📁 {issue.get('filename', 'Unknown')}: linha {issue.get('line_number', '?')}")
            report.append(f"    📝 {issue.get('issue_text', 'No description')}")
            report.append(f"    ⚠️ Severidade: {severity} | Confiança: {confidence}")
            report.append("")
    
    # Detalhes do Safety
    if safety_data.get("vulnerabilities"):
        report.append("🔍 VULNERABILIDADES EM DEPENDÊNCIAS")
        
        for vuln in safety_data["vulnerabilities"][:10]:
            report.append(f"  🔴 {vuln.get('package_name', 'Unknown')} {vuln.get('installed_version', '?')}")
            report.append(f"    📝 {vuln.get('vulnerability_description', 'No description')}")
            report.append(f"    🔗 {vuln.get('vulnerability_id', 'No ID')}")
            report.append("")
    
    # Padrões inseguros
    for pattern_name, findings in pattern_data.items():
        if findings:
            report.append(f"⚠️ PADRÃO INSEGURO: {pattern_name.upper()}")
            
            for finding in findings[:5]:  # Limitar a 5 por padrão
                report.append(f"  📁 {finding['file']}: linha {finding['line']}")
                report.append(f"    📝 {finding['content']}")
            
            if len(findings) > 5:
                report.append(f"    ... e mais {len(findings) - 5} ocorrências")
            
            report.append("")
    
    # Recomendações
    report.append("💡 RECOMENDAÇÕES")
    
    if bandit_issues > 0:
        report.append("  🛡️ Revisar problemas identificados pelo Bandit")
        report.append("     Priorizar issues de severidade HIGH e MEDIUM")
    
    if safety_vulns > 0:
        report.append("  📦 Atualizar dependências vulneráveis")
        report.append("     Executar: pip install --upgrade [package]")
    
    if pattern_issues > 0:
        report.append("  🔍 Revisar padrões inseguros no código")
        report.append("     Implementar práticas de segurança")
    
    if total_issues == 0:
        report.append("  ✅ Nenhuma ação necessária no momento")
        report.append("     Manter monitoramento regular")
    
    return "\n".join(report)

def main():
    """Função principal"""
    
    print("🛡️ INICIANDO AUDITORIA DE SEGURANÇA")
    print("=" * 40)
    
    # Executar ferramentas
    bandit_data = run_bandit_scan()
    safety_data = run_safety_check()
    pattern_data = analyze_code_patterns()
    
    # Gerar relatório
    print("\n📋 Gerando relatório...")
    report = generate_security_report(bandit_data, safety_data, pattern_data)
    
    # Exibir relatório
    print("\n" + report)
    
    # Salvar relatório
    report_file = Path("reports/security_audit.txt")
    report_file.parent.mkdir(exist_ok=True)
    report_file.write_text(report)
    
    print(f"\n💾 Relatório salvo em: {report_file}")
    
    # Determinar código de saída
    total_critical = 0
    
    # Contar problemas críticos
    for issue in bandit_data.get("results", []):
        if issue.get("issue_severity") == "HIGH":
            total_critical += 1
    
    total_critical += len(safety_data.get("vulnerabilities", []))
    
    if total_critical > 0:
        print(f"\n❌ {total_critical} problemas críticos encontrados")
        sys.exit(1)
    else:
        print("\n✅ Nenhum problema crítico encontrado")
        sys.exit(0)

if __name__ == "__main__":
    import re
    main()
```

#### Configuração de CI/CD

**.github/workflows/security.yml**
```yaml
name: Security Audit

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    # Executar toda segunda às 9h
    - cron: '0 9 * * 1'

jobs:
  security:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout código
      uses: actions/checkout@v4
    
    - name: Configurar Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Instalar dependências
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install bandit safety
    
    - name: Executar Bandit
      run: |
        bandit -r . -f json -o bandit-report.json || true
    
    - name: Executar Safety
      run: |
        safety check --json --output safety-report.json || true
    
    - name: Executar auditoria customizada
      run: |
        python scripts/security_audit.py
    
    - name: Upload relatórios
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: security-reports
        path: |
          bandit-report.json
          safety-report.json
          reports/security_audit.txt
    
    - name: Comentar PR com resultados
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const report = fs.readFileSync('reports/security_audit.txt', 'utf8');
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: `## 🛡️ Relatório de Segurança\n\n\`\`\`\n${report}\n\`\`\``
          });
```

#### Checklist de Auditoria
- [ ] Instalar ferramentas de segurança
- [ ] Configurar script de auditoria
- [ ] Executar análise inicial
- [ ] Revisar problemas encontrados
- [ ] Implementar correções necessárias
- [ ] Configurar auditoria automática
- [ ] Integrar com CI/CD

---

## 📚 RECURSOS E DOCUMENTAÇÃO

### Scripts Utilitários

**scripts/run_all_checks.sh**
```bash
#!/bin/bash
# Script para executar todas as verificações

set -e

echo "🚀 EXECUTANDO VERIFICAÇÕES COMPLETAS"
echo "===================================="

# Limpeza inicial
echo "🧹 Limpando arquivos temporários..."
make clean

# Testes de segurança
echo "🛡️ Executando testes de segurança..."
pytest tests/security/ -v -m "security"

# Testes unitários
echo "🧪 Executando testes unitários..."
pytest tests/unit/ -v -m "unit"

# Testes de integração
echo "🔗 Executando testes de integração..."
pytest tests/integration/ -v -m "integration"

# Cobertura
echo "📊 Gerando relatório de cobertura..."
pytest tests/ --cov=app --cov-report=html --cov-report=xml

# Análise de cobertura
echo "📈 Analisando cobertura..."
python scripts/coverage_analysis.py

# Auditoria de segurança
echo "🛡️ Executando auditoria de segurança..."
python scripts/security_audit.py

# Verificação de dependências
echo "📦 Verificando dependências..."
pip check

echo "✅ TODAS AS VERIFICAÇÕES CONCLUÍDAS!"
```

### Configurações Recomendadas

**pyproject.toml**
```toml
[tool.bandit]
exclude_dirs = ["tests", "scripts"]
skips = ["B101", "B601"]  # Ajustar conforme necessário

[tool.coverage.run]
source = ["app.py"]
omit = [
    "tests/*",
    "scripts/*",
    "*/__pycache__/*"
]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise AssertionError",
    "raise NotImplementedError"
]

[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
```

---

## 🎯 CONCLUSÃO DO PLANO

### Status de Implementação

```
✅ CONCLUÍDO
├─ Análise técnica completa
├─ Identificação de vulnerabilidades  
├─ Priorização de ações
└─ Documentação detalhada

🚧 PENDENTE (IMPLEMENTAÇÃO)
├─ 🔴 P0: Correções críticas (20h)
├─ 🟡 P1: Testes e qualidade (32h)
└─ 🟢 P2: Melhorias avançadas (24h)
```

### Próximos Passos

1. **IMEDIATO** - Implementar correções P0 (segurança)
2. **SEMANA 1** - Configurar testes básicos
3. **SEMANA 2-3** - Atingir cobertura 60%+
4. **SEMANA 4** - Implementar melhorias P2

### Critérios de Aprovação para Produção

- ✅ **0 vulnerabilidades críticas**
- ✅ **60%+ cobertura de testes**
- ✅ **Validação robusta implementada**
- ✅ **Subprocess execution segura**
- ✅ **Auditoria de segurança aprovada**

---

**Documento atualizado em**: 02/09/2025  
**Próxima revisão**: Após implementação P0  
**Estimativa total**: 76 horas de desenvolvimento