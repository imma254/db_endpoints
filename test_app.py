from app import app
import unittest


class TestApp(unittest.TestCase):

    # ensure flask was set up correctly
    def test_index(self):
        tester = app.test_client(self)
        response = tester.get('/', content_type='html/text')
        self.assertEqual(response.status_code, 200)

    # ensure login behaves correctly given the correct credentials
    def test_correct_login(self):
        tester = app.test_client(self)
        response = tester.post('/auth/login',
            data=dict(username="manu", password="manu"),
            follow_redirects=True
        )
        self.assertEqual(b'iko sawa')


if __name__ == '__main__':
    unittest.main()
