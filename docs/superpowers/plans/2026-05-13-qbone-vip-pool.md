# QBONE VIP Pool and Redirect Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transition QBONE connectivity verification to a static VIP pool in the `192.178.18.0/23` range and add HTTP 301/302 redirect support to the QUIC client.

**Architecture:** 
- Modify `playbook.yaml` to replace regional hostnames with a list of 20 random VIPs.
- Update `utils.py`'s `verify_quic_connection` to parse status codes and follow `location` headers once.
- Update `siteDiscoveryTool.py` to orchestration the verification using the new `qbone_ips` key.

**Tech Stack:** Python 3, aioquic, PyYAML, pytest (for verification)

---

### Task 1: Setup Testing Environment

**Files:**
- Modify: `requirements.txt`
- Create: `tests/test_qbone_logic.py`

- [ ] **Step 1: Add pytest to requirements.txt**
```python
# Append to requirements.txt
pytest==8.2.0
```

- [ ] **Step 2: Install dependencies**
Run: `pip install -r requirements.txt`

- [ ] **Step 3: Write initial failing tests for redirect logic**
```python
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
```

- [ ] **Step 4: Run tests to verify failure**
Run: `pytest tests/test_qbone_logic.py`
Expected: FAIL (AttributeError or status code mismatch)

- [ ] **Step 5: Commit**
```bash
git add requirements.txt tests/test_qbone_logic.py
git commit -m "test: add requirements and initial redirect test case"
```

---

### Task 2: Implement Redirect Logic in `utils.py`

**Files:**
- Modify: `utils.py`

- [ ] **Step 1: Update `verify_quic_connection` to handle redirects**
```python
# In utils.py: Update verify_quic_connection
def verify_quic_connection(host: str, port: int, proto_name: str = 'QUIC') -> VerifyResults:
    ret = VerifyResults()
    ret.cmd = f'use quic to connect {host}:{port}'
    ret.abstracts['host'] = host
    ret.abstracts['port'] = port
    ret.abstracts['proto'] = proto_name
    
    current_host = host
    current_port = port
    
    for attempt in range(2): # Allow 1 redirect
        if is_ipv4_unicast(current_host):
            ret.abstracts['ip'] = [current_host]
        else:
            dns_results = resolve_dns(current_host)
            ret.abstracts['ip'] = dns_results.abstracts['ip'] if dns_results.bOK else []
            
        try:
            res = quic_client_request([f"https://{current_host}:{current_port}"], include=True, insecure=True)
            headers = res['headers'][0]
            content = res['contents'][0]
            ret.response = headers + content
            ret.abstracts['http_code'] = None
            
            g = re.search(r':status:\s*(\d+)', headers)
            if g:
                status_code = int(g[1])
                ret.abstracts['http_code'] = status_code
                
                if status_code in [301, 302] and attempt == 0:
                    loc = re.search(r'location:\s*(\S+)', headers, re.IGNORECASE)
                    if loc:
                        redirect_url = loc.group(1)
                        parsed = urlparse(redirect_url)
                        current_host = parsed.hostname
                        current_port = parsed.port or 443
                        continue # Follow redirect
                
                if status_code == 200:
                    ret.bOK = True
            break # Exit loop if not a redirect or second attempt
        except Exception as e:
            ret.errReason = type(e).__name__
            ret.response = str(e)
            break
            
    return ret
```

- [ ] **Step 2: Run tests to verify success**
Run: `pytest tests/test_qbone_logic.py`
Expected: PASS

- [ ] **Step 3: Commit**
```bash
git add utils.py
git commit -m "feat: implement redirect following in verify_quic_connection"
```

---

### Task 3: Update Playbook and Tool Orchestration

**Files:**
- Modify: `playbook.yaml`
- Modify: `siteDiscoveryTool.py`

- [ ] **Step 1: Update `playbook.yaml`**
Replace the `qbone:` section with `qbone_ips:`.
```yaml
qbone_ips:
  - "192.178.18.14:443"
  - "192.178.18.37:443"
  - "192.178.18.62:443"
  - "192.178.18.88:443"
  - "192.178.18.115:443"
  - "192.178.18.142:443"
  - "192.178.18.170:443"
  - "192.178.18.198:443"
  - "192.178.18.225:443"
  - "192.178.18.251:443"
  - "192.178.19.12:443"
  - "192.178.19.40:443"
  - "192.178.19.68:443"
  - "192.178.19.95:443"
  - "192.178.19.122:443"
  - "192.178.19.150:443"
  - "192.178.19.177:443"
  - "192.178.19.205:443"
  - "192.178.19.232:443"
  - "192.178.19.254:443"
```

- [ ] **Step 2: Update `siteDiscoveryTool.py` logic**
Modify `verify_playbook_qbone` to handle the new key.
```python
# In siteDiscoveryTool.py
    def verify_playbook_qbone(self):
        proto = 'qbone'
        # Check for both old and new keys for backward compatibility or transition
        config_key = 'qbone_ips' if 'qbone_ips' in self.playbook.keys() else 'qbone'
        
        if config_key not in self.playbook.keys():
            return False
            
        if proto not in self.results.keys():
            self.results[proto] = []
            
        targets = self.playbook[config_key]
        total = len(targets)
        print(f'Verifying {proto.upper()} connections ... 0/{total}', end='')
        
        for i, line in enumerate(targets):
            print(f'\rVerifying {proto.upper()} connections ... {i + 1}/{total}', end='')
            try:
                host, port = line.split(':')
                port = int(port)
            except:
                continue
            con = verify_quic_connection(host, port)
            self.log_result(con)
            self.results[proto].append(con)
            # Ensure IP Range Record is updated
            if 'ip' in con.abstracts and con.abstracts['ip']:
                ips = con.abstracts['ip']
                if isinstance(ips, str):
                    ips = [ips]
                for ip_str in ips:
                    self.iprr.record_tested_net(ip_str)
        print(f'\rVerifying {proto.upper()} connections ... {total}/{total}')
```

- [ ] **Step 3: Add integration test case in `tests/test_qbone_logic.py`**
```python
def test_verify_playbook_qbone_uses_new_key():
    from siteDiscoveryTool import GdccSiteDiscoveryTool
    from utils import GdceIpNetRanges
    
    # Mock playbook and iprr
    mock_tool = MagicMock(spec=GdccSiteDiscoveryTool)
    mock_tool.playbook = {'qbone_ips': ['192.178.18.14:443']}
    mock_tool.results = {}
    mock_tool.iprr = MagicMock()
    mock_tool.logger = MagicMock()
    
    with patch('siteDiscoveryTool.verify_quic_connection') as mock_verify:
        mock_verify.return_value = MagicMock(abstracts={'ip': ['192.178.18.14']})
        
        # We call the actual method on the mock object (if we use a real object it's better)
        GdccSiteDiscoveryTool.verify_playbook_qbone(mock_tool)
        
        assert mock_verify.called
        assert mock_verify.call_args[0][0] == '192.178.18.14'
```

- [ ] **Step 4: Run tests**
Run: `pytest tests/test_qbone_logic.py`
Expected: PASS

- [ ] **Step 5: Commit**
```bash
git add playbook.yaml siteDiscoveryTool.py tests/test_qbone_logic.py
git commit -m "feat: update playbook and tool to use qbone_ips pool"
```

---

### Task 4: Final Integration Run

- [ ] **Step 1: Run the main application with the updated playbook**
Run: `python3 main.py --file playbook.yaml`
Expected: Tool runs successfully, verifies 20 QBONE connections, and generates a report.

- [ ] **Step 2: Verify the report content**
Check if the generated report contains the new VIPs in the QBONE section.

- [ ] **Step 3: Commit**
```bash
git add .
git commit -m "test: final verification of qbone vip pool migration"
```
