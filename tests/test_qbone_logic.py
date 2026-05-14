import pytest
from unittest.mock import patch
from utils import verify_quic_connection

def test_verify_quic_connection_follows_redirect():
    # Mock first response as 301 Redirect
    # Mock second response as 200 OK
    # Mock resolve_dns to avoid real network calls
    with patch('utils.quic_client_request') as mock_request, \
         patch('utils.resolve_dns') as mock_dns:
        
        mock_dns.return_value.bOK = True
        mock_dns.return_value.abstracts = {'ip': ['192.178.18.1']}
        
        mock_request.side_effect = [
            {'headers': [':status: 301\r\nlocation: https://192.178.18.2:443\r\n'], 'contents': ['Moved']},
            {'headers': [':status: 200\r\n'], 'contents': ['Final Content']}
        ]
        
        res = verify_quic_connection('initial-host.google.com', 443)
        
        assert res.bOK is True
        assert res.abstracts['http_code'] == 200
        assert 'Final Content' in res.response
        assert mock_request.call_count == 2

def test_verify_playbook_qbone_uses_new_key():
    from siteDiscoveryTool import SiteDiscoveryTool
    import io
    from unittest.mock import MagicMock
    
    yaml_content = """
qbone_ips:
  - "1.2.3.4:443"
"""
    tool = SiteDiscoveryTool()
    tool.load_playbook(io.StringIO(yaml_content))
    tool.iprr = MagicMock()
    
    with patch('siteDiscoveryTool.verify_quic_connection') as mock_verify:
        mock_verify.return_value.bOK = True
        mock_verify.return_value.abstracts = {'ip': ['1.2.3.4'], 'port': 443, 'proto': 'QUIC', 'host': '1.2.3.4'}
        
        tool.verify_playbook_qbone()
        
        assert mock_verify.called
        assert mock_verify.call_args[0] == ('1.2.3.4', 443)
        assert len(tool.results['qbone']) == 1
