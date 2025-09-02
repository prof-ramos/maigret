import pytest
import subprocess
from unittest.mock import patch, Mock
from app import validate_username_secure, run_maigret_secure, validate_and_display_username

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
            "user1234567890abcdefghijklmnopqrstuvwxyzABCDEFGH"  # 50 chars válidos
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

    def test_validate_and_display_username_success(self):
        """Testa função de validação para display"""
        is_valid, clean_username, error_msg = validate_and_display_username("testuser")
        assert is_valid == True
        assert clean_username == "testuser"
        assert error_msg == ""
    
    def test_validate_and_display_username_failure(self):
        """Testa função de validação para display com erro"""
        is_valid, clean_username, error_msg = validate_and_display_username("user@domain")
        assert is_valid == False
        assert clean_username == ""
        assert "Caracteres não permitidos" in error_msg

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
        assert "--folderoutput" in cmd
        assert "shell" not in kwargs or kwargs["shell"] is False
    
    @patch('subprocess.run')
    def test_parameter_sanitization(self, mock_run):
        """Testa sanitização de parâmetros"""
        mock_run.return_value = Mock(returncode=0, stdout='{}', stderr='')
        
        # Parâmetros válidos
        result = run_maigret_secure(
            username="testuser",
            max_sites=100,
            timeout_sec=60,
            tags=["social", "professional"]
        )
        
        # Verificar sanitização
        args, kwargs = mock_run.call_args
        cmd = args[0]
        
        assert "60" in cmd  # timeout sanitizado
        assert "100" in cmd  # sites sanitizado
        assert "social,professional" in cmd  # tags sanitizadas
    
    def test_invalid_parameters(self):
        """Testa parâmetros inválidos"""
        # Timeout inválido
        with pytest.raises(ValueError, match="Timeout deve estar"):
            run_maigret_secure("testuser", timeout_sec=1000)
        
        # Sites inválidas
        with pytest.raises(ValueError, match="max_sites deve estar"):
            run_maigret_secure("testuser", max_sites=5000)
        
        # ID type inválido
        with pytest.raises(ValueError, match="id_type inválido"):
            run_maigret_secure("testuser", id_type="invalid_type")
    
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
    
    @patch('subprocess.run')
    def test_output_size_limits(self, mock_run):
        """Testa limites de tamanho de saída"""
        # Mock com saída muito grande
        large_output = "x" * 20000
        
        mock_run.return_value = Mock(
            returncode=0,
            stdout=large_output,
            stderr="error" * 2000
        )
        
        result = run_maigret_secure("testuser")
        
        # Verificar truncamento
        assert len(result['stdout']) <= 10000
        assert len(result['stderr']) <= 5000
    
    @patch('subprocess.run')
    def test_tag_validation(self, mock_run):
        """Testa validação de tags"""
        mock_run.return_value = Mock(returncode=0, stdout='{}', stderr='')
        
        # Tags válidas
        result = run_maigret_secure("testuser", tags=["social", "gaming"])
        assert result["success"] == True
        
        # Tags inválidas
        with pytest.raises(ValueError, match="Tag inválida"):
            run_maigret_secure("testuser", tags=["social", "tag@invalid"])