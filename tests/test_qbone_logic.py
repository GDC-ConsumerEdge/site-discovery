import pytest
from unittest.mock import patch, MagicMock
from utils import verify_quic_connection

def test_verify_quic_connection_follows_redirect():
    # Mock first response as 301 Redirect
    # Mock second response as 200 OK
    with patch('utils.quic_client_request') as mock_request:
        mock_request.side_effect = [
            {'headers': ':status: 301\r\nlocation: https://final-destination.google.com:443\r\n', 'contents': ['Moved']},
            {'headers': ':status: 200\r\n', 'contents': ['Final Content']}
        ]
        
        res = verify_quic_connection('initial-host.google.com', 443)
        
        assert res.bOK is True
        assert res.abstracts['http_code'] == 200
        assert 'Final Content' in res.response
        assert mock_request.call_count == 2
