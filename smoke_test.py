"""Simple smoke test that mocks the Anthropic client and verifies
`generate_threat_assessment` returns a string without making network calls.

Run this from the project root inside the `venv311` environment:

    python smoke_test.py

Exit code 0 = success, non-zero = failure.
"""

import types
import sys

# Provide a minimal fake `streamlit` module so we can import `app` during tests
fake_st = types.SimpleNamespace()
fake_st.set_page_config = lambda *a, **k: None
fake_st.markdown = lambda *a, **k: None
fake_st.file_uploader = lambda *a, **k: None
fake_st.text_input = lambda *a, **k: None
fake_st.success = lambda *a, **k: None
fake_st.warning = lambda *a, **k: None
fake_st.info = lambda *a, **k: None
fake_st.error = lambda *a, **k: None
fake_st.empty = lambda *a, **k: types.SimpleNamespace(text=lambda *a, **k: None)
fake_st.progress = lambda *a, **k: types.SimpleNamespace(progress=lambda *a, **k: None)
fake_st.columns = lambda n: [types.SimpleNamespace(__enter__=lambda *a, **k: None, __exit__=lambda *a, **k: None) for _ in range(n)]
class _DummySessionState:
    def __init__(self):
        self._d = {}
    def __contains__(self, key):
        return key in self._d
    def __getattr__(self, name):
        return self._d.get(name, None)
    def __setattr__(self, name, value):
        if name == '_d':
            super().__setattr__(name, value)
        else:
            self._d[name] = value
    def get(self, key, default=None):
        return self._d.get(key, default)

fake_st.session_state = _DummySessionState()

sys.modules['streamlit'] = fake_st

# Provide a minimal fake `anthropic` module so we can import `app` during tests
fake_anthropic = types.SimpleNamespace()
class _AnthropicStub:
    def __init__(self, *a, **k):
        pass

fake_anthropic.Anthropic = _AnthropicStub
sys.modules['anthropic'] = fake_anthropic

# Mock database modules
class _FakeDBSession:
    def execute(self, *args, **kwargs):
        class FakeResult:
            def fetchone(self): return None
        return FakeResult()
    def commit(self): pass
    def rollback(self): pass
    def close(self): pass
    def query(self, *args, **kwargs):
        class FakeQuery:
            def count(self): return 1
            def first(self): return None
            def all(self): return []
            def filter(self, *args, **kwargs): return self
            def order_by(self, *args, **kwargs): return self
        return FakeQuery()

fake_db = types.SimpleNamespace()
fake_db.SessionLocal = lambda: _FakeDBSession()
fake_db.init_db = lambda: None
fake_db.engine = types.SimpleNamespace()
sys.modules['database'] = fake_db

fake_models = types.SimpleNamespace()
class _FakeModel:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        self.id = 1
fake_models.User = _FakeModel
fake_models.Organization = _FakeModel
fake_models.APIKey = _FakeModel
fake_models.AuditLog = _FakeModel
fake_models.ThreatAssessment = _FakeModel
fake_models.UsageStats = _FakeModel
fake_models.APIUsageLog = _FakeModel
sys.modules['models'] = fake_models

# Mock auth module
fake_auth = types.SimpleNamespace()
fake_auth.PasswordAuth = type('PasswordAuth', (), {})
sys.modules['auth'] = fake_auth

# Mock admin dashboard
fake_admin = types.SimpleNamespace()
fake_admin.render_admin_dashboard = lambda: None
sys.modules['admin_dashboard'] = fake_admin

from app import generate_threat_assessment
import anthropic


class FakeCompletion:
    def __init__(self, text: str):
        self.completion = text


class FakeCompletions:
    def create(self, *args, **kwargs):
        # Verify the prompt is formatted for Claude (starts with "\n\nHuman:")
        prompt = kwargs.get('prompt', '') if 'prompt' in kwargs else (args[1] if len(args) > 1 else '')
        if not isinstance(prompt, str) or not prompt.startswith("\n\nHuman:"):
            raise AssertionError("Prompt not prefixed with '\\n\\nHuman:'")
        # Return a fake generated report containing the required sections
        return FakeCompletion(
            "TABLE OF CONTENTS\n- [EXECUTIVE SUMMARY](#executive-summary)\n- [THREAT MODELING ANALYSIS](#threat-modeling-analysis)\n- [REFERENCES](#references)\n\n## EXECUTIVE SUMMARY\nOverall Risk Rating: LOW\nTop 5 Findings:\n- Test finding 1\n- Test finding 2\n\n## THREAT MODELING ANALYSIS\n...\n\n## REFERENCES\n- [NIST SP 800-53] https://csrc.nist.gov/"
        )


class FakeMessages:
    def create(self, *args, **kwargs):
        # Return fake message response with content
        class FakeContent:
            text = "TABLE OF CONTENTS\n- [EXECUTIVE SUMMARY](#executive-summary)\n- [THREAT MODELING ANALYSIS](#threat-modeling-analysis)\n- [REFERENCES](#references)\n\n## EXECUTIVE SUMMARY\nOverall Risk Rating: LOW\nTop 5 Findings:\n- Test finding 1\n- Test finding 2\n\n## THREAT MODELING ANALYSIS\n...\n\n## REFERENCES\n- [NIST SP 800-53] https://csrc.nist.gov/"
        
        class FakeMessage:
            content = [FakeContent()]
        
        return FakeMessage()



class FakeAnthropic:
    def __init__(self, *args, **kwargs):
        self._completions = FakeCompletions()
        # messages is a direct attribute for the modern API
        self.messages = FakeMessages()

    @property
    def completions(self):
        return self._completions


def run_smoke_test():
    import os
    orig = anthropic.Anthropic
    anthropic.Anthropic = FakeAnthropic
    
    # Mock API key in environment for the test
    os.environ['ANTHROPIC_API_KEY'] = 'fake-test-key'

    try:
        from database import SessionLocal
        from models import User
        
        # Create a minimal fake user and db session
        class FakeUser:
            id = 1
            organization_id = 1
            email = 'test@example.com'
        
        class FakeDB:
            def add(self, obj): pass
            def commit(self): pass
            def refresh(self, obj): 
                obj.id = 1
        
        project_info = {
            'name': 'SmokeTest',
            'app_type': 'Web Application',
            'deployment': 'Cloud (AWS)',
            'criticality': 'Low',
            'compliance': ['None'],
            'environment': 'Development'
        }
        documents_content = "# Test Document\nThis is a test."
        framework = 'MITRE ATT&CK'
        risk_areas = ['Agentic AI Risk']

        result, assessment = generate_threat_assessment(
            project_info,
            documents_content,
            framework,
            risk_areas,
            FakeUser(),
            FakeDB()
        )

        if not result or not isinstance(result, str):
            print("SMOKE_TEST: Failed — result is not a string or is empty")
            return 2

        # Verify the report contains required structure
        required = ["TABLE OF CONTENTS", "EXECUTIVE SUMMARY", "REFERENCES"]
        for r in required:
            if r not in result:
                print(f"SMOKE_TEST: Failed — missing required section: {r}")
                return 4

        print("SMOKE_TEST: Success — output snippet:\n", result[:500])
        return 0

    except Exception as e:
        import traceback
        print("SMOKE_TEST: Exception:", e)
        traceback.print_exc()
        return 3

    finally:
        anthropic.Anthropic = orig


if __name__ == '__main__':
    sys.exit(run_smoke_test())
