# 🕵️ Maigret OSINT Interface

Interface web segura e moderna para investigação OSINT usando a ferramenta Maigret, com foco em segurança, validação robusta e práticas de desenvolvimento profissional.

## 🚀 Características

- **🔒 Segurança Aprimorada**: Validação robusta de entrada, proteção contra injeção de comandos
- **🧪 Testes Completos**: Suite de testes automatizados com cobertura mínima de 60%
- **📊 Interface Intuitiva**: Design moderno com Streamlit, fácil de usar
- **⚡ Performance Otimizada**: Execução paralela e timeout configurável
- **📈 Relatórios Detalhados**: Análise completa de resultados com métricas
- **🔧 Configuração Flexível**: Parâmetros ajustáveis para diferentes necessidades

## 📋 Pré-requisitos

- Python 3.11 ou superior
- uv (gerenciador de dependências moderno)
- Maigret instalado e disponível no PATH

## 🛠️ Instalação

### 1. Instalar uv (se ainda não tiver)
```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### 2. Clonar o repositório
```bash
git clone <url-do-repositorio>
cd maigret-osint-interface
```

### 3. Instalar dependências com uv
```bash
# Instalar todas as dependências
uv sync

# Ou instalar individualmente
uv add streamlit pandas pytest pytest-cov bandit safety
```

### 4. Verificar instalação do Maigret
```bash
# Verificar se Maigret está instalado
maigret --version

# Se não estiver instalado:
pip install maigret
```

## 🎯 Uso Rápido

### Executar a aplicação
```bash
# Com uv
uv run streamlit run app.py

# Ou diretamente
streamlit run app.py
```

### Acessar a interface
- Abrir navegador em: http://localhost:8501
- Digitar o username para investigar
- Configurar parâmetros na sidebar
- Clicar em "Iniciar Investigação"

## 🔧 Configuração

### Parâmetros de Busca
- **Timeout**: Tempo máximo por site (5-300 segundos)
- **Máximo de Sites**: Número de sites a verificar (1-1000)
- **Modo Debug**: Ativar logs detalhados
- **Proxy**: Configurar proxy se necessário

### Segurança
- Validação automática de entrada
- Proteção contra injeção de comandos
- Timeout automático para prevenir travamentos
- Logs de segurança estruturados

## 🧪 Desenvolvimento e Testes

### Executar testes
```bash
# Todos os testes
uv run pytest

# Testes com cobertura
uv run pytest --cov=app --cov-report=html

# Testes de segurança
uv run pytest -m security

# Testes de integração
uv run pytest -m integration
```

### Verificação de segurança
```bash
# Análise estática com bandit
uv run bandit -r app.py

# Verificação de vulnerabilidades
uv run safety check

# Verificação de tipos
uv run mypy app.py
```

### Formatação de código
```bash
# Formatar código
uv run black app.py

# Verificar estilo
uv run flake8 app.py
```

## 📊 Estrutura do Projeto

```
maigret-osint-interface/
├── app.py                 # Aplicação principal Streamlit
├── validation.py          # Validação segura de entrada
├── maigret_service.py     # Serviço de execução do Maigret
├── security.py            # Funções de segurança
├── utils.py              # Utilitários auxiliares
├── tests/                # Suite de testes
│   ├── unit/            # Testes unitários
│   ├── integration/     # Testes de integração
│   ├── security/        # Testes de segurança
│   └── conftest.py      # Fixtures globais
├── .cursor/rules/        # Regras Cursor para segurança
├── reports/             # Relatórios de teste e segurança
├── requirements.txt     # Dependências de produção
├── requirements-test.txt # Dependências de teste
├── pytest.ini          # Configuração do pytest
└── README.md           # Este arquivo
```

## 🔐 Segurança

### Validação de Entrada
- Verificação de tipo e comprimento
- Detecção de padrões maliciosos
- Sanitização de caracteres especiais
- Proteção contra injeção de comandos

### Execução Segura
- Uso de lista de argumentos (não shell=True)
- Timeout configurável
- Ambiente isolado
- Tratamento robusto de erros

### Logging e Auditoria
- Logs estruturados de segurança
- Auditoria de sessões
- Monitoramento de tentativas maliciosas
- Relatórios de segurança automáticos

## 📈 Métricas e Monitoramento

### Cobertura de Testes
- Mínimo 60% de cobertura de código
- Testes de segurança obrigatórios
- Testes de integração da interface
- Validação de entrada abrangente

### Performance
- Execução paralela quando possível
- Timeout configurável
- Cache de resultados
- Otimização de memória

## 🚨 Uso Ético

Esta ferramenta deve ser usada exclusivamente para:
- Investigações legítimas e autorizadas
- Pesquisa acadêmica
- Auditoria de segurança própria
- Conformidade com leis locais

**Aviso**: O uso indevido desta ferramenta pode violar leis de privacidade. Use com responsabilidade.

## 🤝 Contribuindo

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

### Diretrizes de Contribuição
- Sempre adicionar testes para novas funcionalidades
- Manter cobertura de testes acima de 60%
- Seguir as regras de segurança estabelecidas
- Usar type hints em todo novo código
- Executar verificações de segurança antes de commit

## 📞 Suporte

- **Issues**: Reporte bugs e solicite features via GitHub Issues
- **Documentação**: Consulte os arquivos `.cursor/rules/` para padrões de código
- **Segurança**: Reporte vulnerabilidades via GitHub Security Advisories

## 📄 Licença

Este projeto está licenciado sob a MIT License - veja o arquivo LICENSE para detalhes.

## 🙏 Agradecimentos

- [Maigret](https://github.com/soxoj/maigret) - Ferramenta base OSINT
- [Streamlit](https://streamlit.io/) - Framework de interface
- Comunidade de segurança e OSINT por feedbacks e contribuições

---

**⚠️ Nota**: Este projeto é uma interface segura para a ferramenta Maigret. A segurança e privacidade são prioridades máximas. Sempre use com responsabilidade e em conformidade com as leis aplicáveis.