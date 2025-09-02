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