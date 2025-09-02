import pytest
from unittest.mock import patch, Mock
from app import init_session_state, get_available_tags, get_maigret_stats

class TestUtilityFunctions:
    """Testes para funções utilitárias"""
    
    def test_init_session_state(self, streamlit_app):
        """Testa inicialização do estado da sessão"""
        # Limpar estado
        for key in list(streamlit_app.session_state.keys()):
            del streamlit_app.session_state[key]
        
        # Executar função
        init_session_state()
        
        # Verificar inicialização
        assert 'search_history' in streamlit_app.session_state
        assert 'current_results' in streamlit_app.session_state
        assert 'search_in_progress' in streamlit_app.session_state
        
        assert isinstance(streamlit_app.session_state.search_history, list)
        assert streamlit_app.session_state.current_results is None
        assert streamlit_app.session_state.search_in_progress is False
    
    def test_get_available_tags(self):
        """Testa obtenção de tags disponíveis"""
        tags = get_available_tags()
        
        assert isinstance(tags, list)
        assert len(tags) > 0
        assert "social" in tags
        assert "gaming" in tags
    
    @patch('subprocess.run')
    def test_get_maigret_stats_success(self, mock_run):
        """Testa obtenção de estatísticas com sucesso"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Sites: 3000+\nCategories: social, gaming, etc."
        )
        
        stats = get_maigret_stats()
        
        assert "Sites: 3000+" in stats
        assert "Categories:" in stats
    
    @patch('subprocess.run')
    def test_get_maigret_stats_error(self, mock_run):
        """Testa obtenção de estatísticas com erro"""
        mock_run.side_effect = Exception("Command not found")
        
        stats = get_maigret_stats()
        
        assert "Erro ao obter estatísticas" in stats
        assert "Command not found" in stats