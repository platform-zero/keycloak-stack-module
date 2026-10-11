#!/usr/bin/env python3
from pathlib import Path
import subprocess
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'stack.config/keycloak/configure-runtime.sh'

class PrivateNativeCredentialsTests(unittest.TestCase):
    def test_native_environment_input_not_password_argv(self):
        text = SOURCE.read_text()
        self.assertNotIn('--password "$KEYCLOAK_ADMIN_PASSWORD"', text)
        start = text.index('KC_CLI_PASSWORD="$KEYCLOAK_ADMIN_PASSWORD"')
        block = text[start:text.index('>/dev/null', start)]
        script = '''set -euo pipefail
KEYCLOAK_ADMIN_PASSWORD=public-source-fixture
KEYCLOAK_ADMIN_USER=fixture-admin
KEYCLOAK_SERVER=http://fixture.invalid
KC=mock_cli
mock_cli() {
 [[ "${KC_CLI_PASSWORD}" == public-source-fixture ]]
 for arg in "$@"; do [[ "$arg" != public-source-fixture && "$arg" != --password ]]; done
}
''' + block + '\n'
        result = subprocess.run(['bash'], input=script, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0)

if __name__ == '__main__':
    unittest.main()
