import pytest
import json
import os
import tempfile
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from gmail_to_s3 import (
    get_header_value,
    sanitize_filename,
    encode_metadata_value,
    calculate_attachments_size,
    get_email_size,
    parse_email_metadata,
    load_existing_index,
    add_to_index,
    get_gmail_service,
    search_large_emails,
    get_email_data,
    extract_attachments,
    upload_to_s3,
    archive_email,
    delete_email,
    verify_s3_upload,
    check_s3_objects_exist,
    upload_index_to_s3,
    main,
    INDEX_FILE,
    SCOPES
)


class TestUtilityFunctions:
    """Test pure utility functions that don't require external calls."""

    def test_get_header_value_existing_header(self):
        headers = [
            {'name': 'Subject', 'value': 'Test Subject'},
            {'name': 'From', 'value': 'test@example.com'},
        ]
        assert get_header_value(headers, 'Subject') == 'Test Subject'
        assert get_header_value(headers, 'From') == 'test@example.com'

    def test_get_header_value_case_insensitive(self):
        headers = [{'name': 'subject', 'value': 'Test Subject'}]
        assert get_header_value(headers, 'Subject') == 'Test Subject'
        assert get_header_value(headers, 'SUBJECT') == 'Test Subject'

    def test_get_header_value_missing_header(self):
        headers = [{'name': 'Subject', 'value': 'Test Subject'}]
        assert get_header_value(headers, 'To') is None

    def test_get_header_value_empty_headers(self):
        assert get_header_value([], 'Subject') is None

    def test_sanitize_filename_basic(self):
        assert sanitize_filename('file.pdf') == 'file.pdf'
        assert sanitize_filename('file with spaces.pdf') == 'file with spaces.pdf'

    def test_sanitize_filename_special_chars(self):
        assert sanitize_filename('file/with/slashes.pdf') == 'file_with_slashes.pdf'
        assert sanitize_filename('file\\back\\slashes.pdf') == 'file_back_slashes.pdf'
        assert sanitize_filename('file..dots.pdf') == 'file_dots.pdf'

    def test_sanitize_filename_non_ascii(self):
        # Non-ASCII chars should be URL encoded
        result = sanitize_filename('fileñame.pdf')
        assert result == 'file%C3%B1ame.pdf'

    def test_encode_metadata_value_basic(self):
        assert encode_metadata_value('simple text') == 'simple%20text'

    def test_encode_metadata_value_empty(self):
        assert encode_metadata_value('') == ''

    def test_encode_metadata_value_none(self):
        assert encode_metadata_value(None) == ''

    def test_encode_metadata_value_special_chars(self):
        assert encode_metadata_value('fileñame.pdf') == 'file%C3%B1ame.pdf'

    def test_calculate_attachments_size_empty(self):
        assert calculate_attachments_size([]) == 0.0

    def test_calculate_attachments_size_single_attachment(self):
        attachments = [{'size': 1024 * 1024}]  # 1MB
        assert calculate_attachments_size(attachments) == 1.0

    def test_calculate_attachments_size_multiple_attachments(self):
        attachments = [
            {'size': 1024 * 1024},  # 1MB
            {'size': 2 * 1024 * 1024},  # 2MB
        ]
        assert calculate_attachments_size(attachments) == 3.0

    def test_get_email_size_zero(self):
        email_data = {'sizeEstimate': 0}
        assert get_email_size(email_data) == 0.0

    def test_get_email_size_with_estimate(self):
        email_data = {'sizeEstimate': 1024 * 1024}  # 1MB
        assert get_email_size(email_data) == 1.0

    def test_get_email_size_missing_estimate(self):
        email_data = {}
        assert get_email_size(email_data) == 0.0


class TestParsingFunctions:
    """Test email parsing and metadata extraction."""

    def test_parse_email_metadata_complete_headers(self):
        email_data = {
            'payload': {
                'headers': [
                    {'name': 'Subject', 'value': 'Test Subject'},
                    {'name': 'From', 'value': 'sender@example.com'},
                    {'name': 'To', 'value': 'recipient@example.com'},
                    {'name': 'Date', 'value': 'Mon, 01 Jan 2024 10:00:00 +0000'},
                ]
            },
            'internalDate': '1704105600000',  # 2024-01-01 10:00:00 UTC
            'labelIds': ['INBOX', 'IMPORTANT'],
            'sizeEstimate': 1024 * 1024
        }

        metadata = parse_email_metadata(email_data)

        assert metadata['subject'] == 'Test Subject'
        assert metadata['from'] == 'sender@example.com'
        assert metadata['to'] == 'recipient@example.com'
        assert metadata['date'] == 'Mon, 01 Jan 2024 10:00:00 +0000'
        assert metadata['labels'] == ['INBOX', 'IMPORTANT']
        assert metadata['size_bytes'] == 1024 * 1024
        assert metadata['size_mb'] == 1.0
        assert 'date_parsed' in metadata

    def test_parse_email_metadata_missing_headers(self):
        email_data = {
            'payload': {'headers': []},
            'internalDate': '1704105600000',
            'labelIds': [],
            'sizeEstimate': 0
        }

        metadata = parse_email_metadata(email_data)

        assert metadata['subject'] == '(No Subject)'
        assert metadata['from'] == ''
        assert metadata['to'] == ''
        assert metadata['date'] == ''
        assert metadata['labels'] == []
        assert metadata['size_bytes'] == 0
        assert metadata['size_mb'] == 0.0

    def test_parse_email_metadata_malformed_date(self):
        email_data = {
            'payload': {
                'headers': [
                    {'name': 'Date', 'value': 'invalid date'},
                ]
            },
            'internalDate': '1704105600000',
            'labelIds': [],
            'sizeEstimate': 0
        }

        metadata = parse_email_metadata(email_data)

        # Should fall back to internalDate
        assert metadata['date_parsed'] is not None
        assert isinstance(metadata['date_parsed'], str)


class TestIndexFunctions:
    """Test index loading and writing functions."""

    def test_load_existing_index_no_file(self):
        """Test loading when index file doesn't exist."""
        with patch('os.path.exists', return_value=False):
            result = load_existing_index()
            assert result == {}

    def test_load_existing_index_empty_file(self, tmp_path):
        """Test loading an empty index file."""
        index_file = tmp_path / INDEX_FILE
        index_file.write_text('')

        with patch('gmail_to_s3.INDEX_FILE', str(index_file)):
            result = load_existing_index()
            assert result == {}

    def test_load_existing_index_valid_entries(self, tmp_path):
        """Test loading valid index entries."""
        index_file = tmp_path / INDEX_FILE
        entries = [
            {
                'msg_id': 'msg1',
                'uploaded': True,
                'archived': False,
                'deleted': False,
                's3_paths': ['path1'],
                'size_bytes': 1000
            },
            {
                'msg_id': 'msg2',
                'uploaded': False,
                'archived': True,
                'deleted': False,
                's3_paths': [],
                'size_bytes': 2000
            }
        ]
        content = '\n'.join(json.dumps(entry) for entry in entries) + '\n'
        index_file.write_text(content)

        with patch('gmail_to_s3.INDEX_FILE', str(index_file)):
            result = load_existing_index()

            assert len(result) == 2
            assert result['msg1']['uploaded'] is True
            assert result['msg2']['archived'] is True

    def test_load_existing_index_invalid_json(self, tmp_path):
        """Test loading index with invalid JSON."""
        index_file = tmp_path / INDEX_FILE
        index_file.write_text('invalid json\n{"msg_id": "msg1"}\n')

        with patch('gmail_to_s3.INDEX_FILE', str(index_file)):
            with patch('gmail_to_s3.logger') as mock_logger:
                result = load_existing_index()
                mock_logger.warning.assert_called()
                # Should still load the valid entry
                assert 'msg1' in result

    def test_add_to_index_dry_run(self, tmp_path):
        """Test adding to index in dry run mode."""
        index_file = tmp_path / INDEX_FILE

        with patch('gmail_to_s3.INDEX_FILE', str(index_file)):
            with patch('gmail_to_s3.logger') as mock_logger:
                add_to_index(
                    msg_id='msg1',
                    metadata={
                        'subject': 'Test',
                        'from': 'test@example.com',
                        'to': 'recipient@example.com',
                        'date_parsed': '2024-01-01T10:00:00',
                        'size_mb': 1.0,
                        'size_bytes': 1000,
                        'labels': []
                    },
                    s3_paths=['path1'],
                    uploaded=True,
                    archived=False,
                    deleted=False,
                    dry_run=True
                )

                mock_logger.info.assert_called_once()
                # File should not exist since it's dry run
                assert not index_file.exists()

    def test_add_to_index_actual_write(self, tmp_path):
        """Test actually writing to index file."""
        index_file = tmp_path / INDEX_FILE

        with patch('gmail_to_s3.INDEX_FILE', str(index_file)):
            add_to_index(
                msg_id='msg1',
                metadata={
                    'subject': 'Test',
                    'from': 'test@example.com',
                    'to': 'recipient@example.com',
                    'date_parsed': '2024-01-01T10:00:00',
                    'size_mb': 1.0,
                    'size_bytes': 1000,
                    'labels': []
                },
                s3_paths=['path1'],
                uploaded=True,
                archived=False,
                deleted=False,
                dry_run=False
            )

            assert index_file.exists()
            content = index_file.read_text()
            entry = json.loads(content.strip())

            assert entry['msg_id'] == 'msg1'
            assert entry['uploaded'] is True
            assert entry['s3_paths'] == ['path1']


class TestExternalAPIFunctions:
    """Test functions that interact with external APIs using mocks."""

    @patch('gmail_to_s3.pickle.dump')
    @patch('gmail_to_s3.pickle.load')
    @patch('gmail_to_s3.os.path.exists')
    @patch('gmail_to_s3.InstalledAppFlow.from_client_secrets_file')
    @patch('gmail_to_s3.build')
    def test_get_gmail_service_new_credentials(self, mock_build, mock_flow_class, mock_exists, mock_pickle_load, mock_pickle_dump):
        """Test getting Gmail service when no token exists."""
        mock_exists.return_value = False
        mock_flow_instance = Mock()
        mock_creds = Mock()
        mock_creds.valid = False
        mock_creds.expired = False
        mock_flow_instance.run_local_server.return_value = mock_creds
        mock_flow_class.return_value = mock_flow_instance

        service = get_gmail_service()

        mock_flow_class.assert_called_once_with('credentials.json', SCOPES)
        mock_build.assert_called_once_with('gmail', 'v1', credentials=mock_creds)

    @patch('gmail_to_s3.pickle.dump')
    @patch('gmail_to_s3.pickle.load')
    @patch('gmail_to_s3.os.path.exists')
    @patch('gmail_to_s3.Request')
    @patch('gmail_to_s3.build')
    def test_get_gmail_service_refresh_token(self, mock_build, mock_request, mock_exists, mock_pickle_load, mock_pickle_dump):
        """Test getting Gmail service when credentials need refresh."""
        mock_exists.return_value = True
        mock_creds = Mock()
        mock_creds.valid = False
        mock_creds.expired = True
        mock_creds.refresh_token = True
        mock_pickle_load.return_value = mock_creds

        service = get_gmail_service()

        mock_creds.refresh.assert_called_once_with(mock_request())
        mock_build.assert_called_once_with('gmail', 'v1', credentials=mock_creds)

    @patch('gmail_to_s3.pickle.load')
    @patch('gmail_to_s3.os.path.exists')
    @patch('gmail_to_s3.build')
    def test_get_gmail_service_valid_token(self, mock_build, mock_exists, mock_pickle_load):
        """Test getting Gmail service with valid existing token."""
        mock_exists.return_value = True
        mock_creds = Mock()
        mock_creds.valid = True
        mock_pickle_load.return_value = mock_creds

        service = get_gmail_service()

        mock_build.assert_called_once_with('gmail', 'v1', credentials=mock_creds)

    def test_search_large_emails(self):
        """Test searching for large emails."""
        mock_service = Mock()
        mock_list_response = {
            'messages': [
                {'id': 'msg1'},
                {'id': 'msg2'}
            ],
            'nextPageToken': None
        }
        mock_service.users().messages().list().execute.return_value = mock_list_response

        messages = search_large_emails(mock_service, size_mb=10, older_than_years=1)

        assert messages == [{'id': 'msg1'}, {'id': 'msg2'}]
        mock_service.users().messages().list.assert_called_with(
            userId='me',
            q='size:10m older_than:1y'
        )

    def test_search_large_emails_with_pagination(self):
        """Test searching with pagination."""
        mock_service = Mock()
        mock_list_response1 = {
            'messages': [{'id': 'msg1'}],
            'nextPageToken': 'token1'
        }
        mock_list_response2 = {
            'messages': [{'id': 'msg2'}],
            'nextPageToken': None
        }
        mock_service.users().messages().list().execute.side_effect = [
            mock_list_response1, mock_list_response2
        ]

        messages = search_large_emails(mock_service, size_mb=10, older_than_years=1)

        assert messages == [{'id': 'msg1'}, {'id': 'msg2'}]

    def test_get_email_data(self):
        """Test fetching full email data."""
        mock_service = Mock()
        mock_email_data = {'id': 'msg1', 'payload': {}}
        mock_service.users().messages().get().execute.return_value = mock_email_data

        result = get_email_data(mock_service, 'msg1')

        assert result == mock_email_data
        mock_service.users().messages().get.assert_called_with(
            userId='me', id='msg1', format='full'
        )

    def test_extract_attachments_no_attachments(self):
        """Test extracting attachments when there are none."""
        parts = []
        result = extract_attachments(None, 'msg1', parts, dry_run=False)
        assert result == []

    def test_extract_attachments_with_attachments(self):
        """Test extracting attachments from parts."""
        mock_service = Mock()
        parts = [
            {
                'filename': 'test.pdf',
                'mimeType': 'application/pdf',
                'body': {
                    'attachmentId': 'att1',
                    'size': 1000
                }
            }
        ]

        mock_attachment = {'data': b'fake_data'}
        mock_service.users().messages().attachments().get().execute.return_value = mock_attachment

        with patch('gmail_to_s3.base64.urlsafe_b64decode', return_value=b'decoded_data'):
            result = extract_attachments(mock_service, 'msg1', parts, dry_run=False)

            assert len(result) == 1
            assert result[0]['filename'] == 'test.pdf'
            assert result[0]['data'] == b'decoded_data'

    def test_extract_attachments_dry_run(self):
        """Test extracting attachments in dry run mode."""
        parts = [
            {
                'filename': 'test.pdf',
                'mimeType': 'application/pdf',
                'body': {
                    'attachmentId': 'att1',
                    'size': 1000
                }
            }
        ]

        result = extract_attachments(None, 'msg1', parts, dry_run=True)

        assert len(result) == 1
        assert result[0]['filename'] == 'test.pdf'
        assert result[0]['data'] is None

    def test_extract_attachments_nested_parts(self):
        """Test extracting from nested parts structure."""
        parts = [
            {
                'parts': [
                    {
                        'filename': 'test.pdf',
                        'mimeType': 'application/pdf',
                        'body': {
                            'attachmentId': 'att1',
                            'size': 1000
                        }
                    }
                ]
            }
        ]

        result = extract_attachments(None, 'msg1', parts, dry_run=True)

        assert len(result) == 1
        assert result[0]['filename'] == 'test.pdf'

    @patch('gmail_to_s3.datetime')
    def test_upload_to_s3_dry_run(self, mock_datetime):
        """Test uploading to S3 in dry run mode."""
        mock_datetime.fromtimestamp.return_value = datetime(2024, 1, 1)
        mock_s3_client = Mock()

        email_data = {'internalDate': '1704105600000'}  # 2024-01-01
        attachments = [
            {'filename': 'test.pdf', 'mime_type': 'application/pdf', 'size': 1000, 'data': b'fake_data'}
        ]

        with patch('gmail_to_s3.logger') as mock_logger:
            result = upload_to_s3(mock_s3_client, email_data, 'msg1', attachments, 'test-bucket', dry_run=True)

            assert len(result) == 2  # email.json + attachment
            mock_logger.info.assert_called()
            # Should not call S3 put_object in dry run
            mock_s3_client.put_object.assert_not_called()

    @patch('gmail_to_s3.datetime')
    def test_upload_to_s3_actual_upload(self, mock_datetime):
        """Test actual upload to S3."""
        mock_datetime.fromtimestamp.return_value = datetime(2024, 1, 1)
        mock_s3_client = Mock()

        email_data = {'internalDate': '1704105600000'}
        attachments = [
            {'filename': 'test.pdf', 'mime_type': 'application/pdf', 'size': 1000, 'data': b'fake_data'}
        ]

        with patch('gmail_to_s3.sanitize_filename', return_value='test.pdf'):
            with patch('gmail_to_s3.encode_metadata_value', return_value='test.pdf'):
                with patch('gmail_to_s3.logger') as mock_logger:
                    result = upload_to_s3(mock_s3_client, email_data, 'msg1', attachments, 'test-bucket', dry_run=False)

                    assert len(result) == 2
                    assert mock_s3_client.put_object.call_count == 2  # email + attachment

    def test_archive_email_dry_run(self):
        """Test archiving email in dry run mode."""
        mock_service = Mock()

        with patch('gmail_to_s3.logger') as mock_logger:
            archive_email(mock_service, 'msg1', dry_run=True)

            mock_logger.info.assert_called_with("  [DRY RUN] Would archive email in Gmail")
            mock_service.users().messages().modify.assert_not_called()

    def test_archive_email_actual(self):
        """Test actually archiving email."""
        mock_service = Mock()

        archive_email(mock_service, 'msg1', dry_run=False)

        mock_service.users().messages().modify.assert_called_with(
            userId='me',
            id='msg1',
            body={'removeLabelIds': ['INBOX']}
        )

    def test_delete_email_dry_run(self):
        """Test deleting email in dry run mode."""
        mock_service = Mock()

        with patch('gmail_to_s3.logger') as mock_logger:
            delete_email(mock_service, 'msg1', dry_run=True)

            mock_logger.warning.assert_called_with("  [DRY RUN] Would PERMANENTLY DELETE email from Gmail")
            mock_service.users().messages().trash.assert_not_called()

    def test_delete_email_actual(self):
        """Test actually deleting email."""
        mock_service = Mock()

        delete_email(mock_service, 'msg1', dry_run=False)

        mock_service.users().messages().trash.assert_called_with(
            userId='me',
            id='msg1'
        )

    def test_verify_s3_upload_dry_run(self):
        """Test verifying S3 upload in dry run."""
        result = verify_s3_upload(None, 'bucket', ['path1'], dry_run=True)
        assert result is True

    def test_verify_s3_upload_success(self):
        """Test successful S3 verification."""
        mock_s3_client = Mock()
        mock_s3_client.head_object.return_value = {'ContentLength': 1000}

        result = verify_s3_upload(mock_s3_client, 'bucket', ['path1'], dry_run=False)

        assert result is True
        mock_s3_client.head_object.assert_called_with(Bucket='bucket', Key='path1')

    def test_verify_s3_upload_failure(self):
        """Test failed S3 verification."""
        mock_s3_client = Mock()
        mock_s3_client.head_object.side_effect = Exception("S3 error")

        result = verify_s3_upload(mock_s3_client, 'bucket', ['path1'], dry_run=False)

        assert result is False

    def test_check_s3_objects_exist_success(self):
        """Test checking S3 objects exist successfully."""
        mock_s3_client = Mock()
        mock_s3_client.head_object.return_value = {'ContentLength': 1000}

        all_exist, size_matches = check_s3_objects_exist(mock_s3_client, 'bucket', ['path1'], 1000)

        assert all_exist is True
        assert size_matches is True

    def test_check_s3_objects_exist_size_mismatch(self):
        """Test S3 size mismatch."""
        mock_s3_client = Mock()
        mock_s3_client.head_object.return_value = {'ContentLength': 2000}  # Much larger

        all_exist, size_matches = check_s3_objects_exist(mock_s3_client, 'bucket', ['path1'], 1000)

        assert all_exist is True
        assert size_matches is False

    def test_check_s3_objects_exist_failure(self):
        """Test S3 check failure."""
        mock_s3_client = Mock()
        mock_s3_client.head_object.side_effect = Exception("Not found")

        all_exist, size_matches = check_s3_objects_exist(mock_s3_client, 'bucket', ['path1'])

        assert all_exist is False
        assert size_matches is False

    @patch('gmail_to_s3.os.path.exists')
    def test_upload_index_to_s3_no_file(self, mock_exists):
        """Test uploading index when file doesn't exist."""
        mock_exists.return_value = False

        upload_index_to_s3(None, 'bucket', dry_run=False)
        # Should return early, no assertions needed

    @patch('gmail_to_s3.os.path.exists')
    @patch('builtins.open', new_callable=MagicMock)
    def test_upload_index_to_s3_dry_run(self, mock_open, mock_exists):
        """Test uploading index in dry run."""
        mock_exists.return_value = True

        with patch('gmail_to_s3.logger') as mock_logger:
            upload_index_to_s3(None, 'bucket', dry_run=True)

            mock_logger.info.assert_called()

    @patch('gmail_to_s3.os.path.exists')
    @patch('builtins.open', new_callable=MagicMock)
    def test_upload_index_to_s3_actual(self, mock_open, mock_exists):
        """Test actually uploading index."""
        mock_exists.return_value = True
        mock_s3_client = Mock()

        with patch('gmail_to_s3.logger') as mock_logger:
            upload_index_to_s3(mock_s3_client, 'bucket', dry_run=False)

            mock_s3_client.put_object.assert_called()


class TestMainFunction:
    """Test the main function with mocked arguments and services."""

    @patch('gmail_to_s3.argparse.ArgumentParser.parse_args')
    @patch('gmail_to_s3.get_gmail_service')
    @patch('gmail_to_s3.boto3.client')
    @patch('gmail_to_s3.load_existing_index')
    @patch('gmail_to_s3.search_large_emails')
    @patch('gmail_to_s3.get_email_data')
    @patch('gmail_to_s3.parse_email_metadata')
    @patch('gmail_to_s3.extract_attachments')
    @patch('gmail_to_s3.calculate_attachments_size')
    @patch('gmail_to_s3.upload_to_s3')
    @patch('gmail_to_s3.add_to_index')
    @patch('gmail_to_s3.verify_s3_upload')
    @patch('gmail_to_s3.logger')
    def test_main_basic_flow(self, mock_logger, mock_verify, mock_add_index, mock_upload_s3,
                            mock_calc_size, mock_extract, mock_parse, mock_get_email,
                            mock_search, mock_load_index, mock_boto3, mock_get_service, mock_parse_args):
        """Test main function with basic successful flow."""
        # Setup mocks
        mock_args = Mock()
        mock_args.s3_bucket = 'test-bucket'
        mock_args.dry_run = False
        mock_args.size_mb = 10
        mock_args.older_than_years = 1
        mock_args.archive_gmail = False
        mock_args.delete_gmail = False
        mock_args.i_understand_deletion_is_permanent = False
        mock_args.max_emails = None
        mock_args.force_reprocess = False
        mock_args.log_level = 'INFO'
        mock_parse_args.return_value = mock_args

        mock_service = Mock()
        mock_get_service.return_value = mock_service

        mock_search.return_value = [{'id': 'msg1'}]
        mock_get_email.return_value = {'internalDate': '1704105600000', 'payload': {'parts': []}}
        mock_parse.return_value = {
            'subject': 'Test', 'from': 'test@example.com', 'to': 'to@example.com',
            'date_parsed': '2024-01-01T10:00:00', 'size_mb': 15.0, 'size_bytes': 15*1024*1024,
            'labels': []
        }
        mock_extract.return_value = []
        mock_calc_size.return_value = 0.0
        mock_upload_s3.return_value = ['path1']
        mock_verify.return_value = True
        mock_load_index.return_value = {}

        # Run main
        main()

        # Verify calls
        mock_get_service.assert_called_once()
        mock_search.assert_called_once_with(mock_service, size_mb=10, older_than_years=1)
        mock_get_email.assert_called_once()
        mock_upload_s3.assert_called_once()
        mock_verify.assert_called_once()

    @patch('gmail_to_s3.argparse.ArgumentParser.parse_args')
    def test_main_deletion_safety_check(self, mock_parse_args):
        """Test that main exits when deletion safety check fails."""
        mock_args = Mock()
        mock_args.delete_gmail = True
        mock_args.i_understand_deletion_is_permanent = False
        mock_parse_args.return_value = mock_args

        with patch('gmail_to_s3.logger') as mock_logger:
            main()

            mock_logger.error.assert_called()

    @patch('gmail_to_s3.argparse.ArgumentParser.parse_args')
    def test_main_conflicting_flags(self, mock_parse_args):
        """Test that main exits when both archive and delete are specified."""
        mock_args = Mock()
        mock_args.delete_gmail = True
        mock_args.archive_gmail = True
        mock_args.i_understand_deletion_is_permanent = True
        mock_parse_args.return_value = mock_args

        with patch('gmail_to_s3.logger') as mock_logger:
            main()

            mock_logger.error.assert_called()


if __name__ == '__main__':
    pytest.main([__file__])