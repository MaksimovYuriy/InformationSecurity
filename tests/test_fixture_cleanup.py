import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
from scripts.verify_public_access import main


class FixtureCleanupTests(unittest.TestCase):
    def test_empty_owned_bucket_is_deleted_even_when_object_creation_failed(self):
        provider = Mock()
        provider._client.put_object.side_effect = ClientError({'Error': {'Code': 'AccessDenied'}}, 'PutObject')
        provider._client.put_object_acl.side_effect = ClientError({'Error': {'Code': 'NoSuchKey'}}, 'PutObjectAcl')
        with tempfile.TemporaryDirectory() as directory, \
             patch('scripts.verify_public_access.S3Provider.from_settings', return_value=provider), \
             patch('scripts.verify_public_access.load_s3_settings', return_value=Mock()), \
             patch('scripts.verify_public_access.Path', return_value=Path(directory)), \
             patch('sys.argv', ['fixture', '--run-training-fixture']), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(), 2)
        provider._client.delete_bucket.assert_called_once()
