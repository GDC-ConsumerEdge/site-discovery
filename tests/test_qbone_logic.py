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
