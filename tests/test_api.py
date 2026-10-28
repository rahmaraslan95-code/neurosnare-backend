import unittest
try:
    from fastapi.testclient import TestClient
    from app.main import app
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

@unittest.skipUnless(AVAILABLE, "Install backend/requirements.txt to run API integration tests")
class ApiIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.client = TestClient(app)
    def test_health_is_public(self):
        self.assertEqual(self.client.get('/api/v1/health').status_code, 200)
    def test_events_require_bearer_auth(self):
        self.assertEqual(self.client.get('/api/v1/events').status_code, 401)
    def test_login_then_events(self):
        login = self.client.post('/api/v1/auth/login', json={'username':'analyst','password':'demo-only-change-me'})
        self.assertEqual(login.status_code, 200)
        token = login.json()['access_token']
        response = self.client.get('/api/v1/events', headers={'Authorization':'Bearer '+token})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 12)

if __name__ == '__main__': unittest.main()
