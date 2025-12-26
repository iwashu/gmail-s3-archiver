from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import boto3
import base64
import os
import pickle
import json
import argparse
import logging
from datetime import datetime
from email.utils import parsedate_to_datetime
import urllib.parse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
INDEX_FILE = 'email_index.jsonl'

def get_gmail_service():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    
    return build('gmail', 'v1', credentials=creds)

def search_large_emails(service, size_mb=10, older_than_years=1):
    """Search for emails larger than size_mb and older than specified years
    
    Note: This searches for emails where the TOTAL email size (including attachments)
    is larger than size_mb. We'll filter further based on attachment sizes later.
    """
    query = f'size:{size_mb}m older_than:{older_than_years}y'
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])
    
    while 'nextPageToken' in results:
        page_token = results['nextPageToken']
        results = service.users().messages().list(
            userId='me', q=query, pageToken=page_token).execute()
        messages.extend(results.get('messages', []))
    
    return messages

def calculate_attachments_size(attachments):
    """Calculate total size of attachments in MB"""
    total_bytes = sum(att['size'] for att in attachments)
    return total_bytes / (1024 * 1024)

def get_email_data(service, msg_id):
    """Fetch full email data"""
    message = service.users().messages().get(
        userId='me', id=msg_id, format='full').execute()
    return message

def get_email_size(email_data):
    """Calculate email size in MB"""
    size_bytes = email_data.get('sizeEstimate', 0)
    return size_bytes / (1024 * 1024)

def get_header_value(headers, name):
    """Extract header value by name"""
    for header in headers:
        if header['name'].lower() == name.lower():
            return header['value']
    return None

def parse_email_metadata(email_data):
    """Extract key metadata from email"""
    headers = email_data.get('payload', {}).get('headers', [])
    
    subject = get_header_value(headers, 'Subject') or '(No Subject)'
    from_addr = get_header_value(headers, 'From') or ''
    to_addr = get_header_value(headers, 'To') or ''
    date_str = get_header_value(headers, 'Date') or ''
    
    # Parse date
    try:
        date_obj = parsedate_to_datetime(date_str) if date_str else None
    except:
        date_obj = None
    
    timestamp = int(email_data.get('internalDate', 0)) / 1000
    date = datetime.fromtimestamp(timestamp)
    
    return {
        'subject': subject,
        'from': from_addr,
        'to': to_addr,
        'date': date_str,
        'date_parsed': date_obj.isoformat() if date_obj else date.isoformat(),
        'labels': email_data.get('labelIds', []),
        'size_bytes': email_data.get('sizeEstimate', 0),
        'size_mb': get_email_size(email_data)
    }

def extract_attachments(service, msg_id, parts, dry_run=False):
    """Extract attachments from email parts"""
    attachments = []
    
    def process_parts(parts_list):
        for part in parts_list:
            # Check for nested parts
            if 'parts' in part:
                process_parts(part['parts'])
            
            filename = part.get('filename')
            if filename:
                attachment_id = part['body'].get('attachmentId')
                mime_type = part.get('mimeType', 'application/octet-stream')
                size = part['body'].get('size', 0)
                
                attachment_data = None
                if attachment_id and not dry_run:
                    # Download attachment
                    att = service.users().messages().attachments().get(
                        userId='me',
                        messageId=msg_id,
                        id=attachment_id
                    ).execute()
                    attachment_data = base64.urlsafe_b64decode(att['data'])
                
                attachments.append({
                    'filename': filename,
                    'mime_type': mime_type,
                    'size': size,
                    'data': attachment_data
                })
    
    if parts:
        process_parts(parts)
    
    return attachments

def sanitize_filename(filename):
    """Sanitize filename for S3 and remove non-ASCII characters"""
    # Replace problematic characters
    sanitized = filename.replace('/', '_').replace('\\', '_').replace('..', '_')
    # URL encode to handle non-ASCII characters
    sanitized = urllib.parse.quote(sanitized, safe='.-_ ')
    return sanitized

def encode_metadata_value(value):
    """Encode metadata value to ASCII-safe string using URL encoding"""
    if not value:
        return ''
    # URL encode the value to make it ASCII-safe
    return urllib.parse.quote(value, safe='')

def upload_to_s3(s3_client, email_data, msg_id, attachments, s3_bucket, dry_run=False):
    """Upload email data and attachments to S3 Glacier Deep Archive"""
    timestamp = int(email_data.get('internalDate', 0)) / 1000
    date = datetime.fromtimestamp(timestamp)
    base_path = f"emails/{date.year}/{date.month:02d}/{msg_id}"
    
    uploaded_files = []
    
    # Upload main email JSON
    email_key = f"{base_path}/email.json"
    if dry_run:
        logger.info("  [DRY RUN] Would upload to s3://%s/%s", s3_bucket, email_key)
    else:
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=email_key,
            Body=json.dumps(email_data, indent=2),
            ContentType='application/json',
            StorageClass='DEEP_ARCHIVE'
        )
    uploaded_files.append(email_key)
    
    # Upload attachments
    for i, att in enumerate(attachments):
        # Sanitize filename for S3 key
        safe_filename = sanitize_filename(att['filename'])
        att_key = f"{base_path}/attachments/{safe_filename}"
        att_size_kb = att['size'] / 1024
        
        if dry_run:
            logger.info("  [DRY RUN] Would upload attachment: %s (%.1f KB)", att['filename'], att_size_kb)
        else:
            # Encode metadata values to ASCII
            encoded_filename = encode_metadata_value(att['filename'])
            
            s3_client.put_object(
                Bucket=s3_bucket,
                Key=att_key,
                Body=att['data'],
                ContentType=att['mime_type'],
                StorageClass='DEEP_ARCHIVE',
                Metadata={
                    'original-filename': encoded_filename,
                    'email-id': msg_id
                }
            )
            logger.info("  ✓ Uploaded attachment: %s (%.1f KB)", att['filename'], att_size_kb)
        uploaded_files.append(att_key)
    
    return uploaded_files

def load_existing_index():
    """Load existing index to check for already-processed emails
    
    Returns a dict mapping msg_id to their processing status:
    {
        'msg_id': {
            'uploaded': bool,
            'archived': bool,
            'deleted': bool,
            's3_paths': [...]
        }
    }
    """
    processed_emails = {}
    if not os.path.exists(INDEX_FILE):
        logger.debug("No existing index file found")
        return processed_emails
    
    try:
        with open(INDEX_FILE, 'r') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    entry = json.loads(line.strip())
                    msg_id = entry.get('msg_id')
                    if msg_id:
                        processed_emails[msg_id] = {
                            'uploaded': entry.get('uploaded', False),
                            'archived': entry.get('archived', False),
                            'deleted': entry.get('deleted', False),
                            's3_paths': entry.get('s3_paths', []),
                            'size_bytes': entry.get('size_bytes', 0)
                        }
                except json.JSONDecodeError as e:
                    logger.warning("Skipping invalid JSON at line %d in index: %s", line_num, e)
        logger.info("Loaded %d already-processed email IDs from index", len(processed_emails))
    except Exception as e:
        logger.error("Error loading index file: %s", e)
    
    return processed_emails

def check_s3_objects_exist(s3_client, s3_bucket, s3_paths, expected_size_bytes=None):
    """Check if S3 objects exist and optionally verify size
    
    Returns (all_exist, size_matches)
    """
    try:
        total_size = 0
        for path in s3_paths:
            response = s3_client.head_object(Bucket=s3_bucket, Key=path)
            total_size += response.get('ContentLength', 0)
        
        size_matches = True
        if expected_size_bytes is not None:
            # Allow 5% size difference for encoding overhead
            size_diff_ratio = abs(total_size - expected_size_bytes) / max(expected_size_bytes, 1)
            size_matches = size_diff_ratio < 0.05
        
        return True, size_matches
    except Exception as e:
        logger.debug("S3 check failed: %s", e)
        return False, False

def add_to_index(msg_id, metadata, s3_paths, uploaded=False, archived=False, deleted=False, dry_run=False):
    """Add email to search index"""
    index_entry = {
        'msg_id': msg_id,
        'timestamp': datetime.now().isoformat(),
        'subject': metadata['subject'],
        'from': metadata['from'],
        'to': metadata['to'],
        'date': metadata['date_parsed'],
        'size_mb': metadata['size_mb'],
        'size_bytes': metadata['size_bytes'],
        'labels': metadata['labels'],
        's3_paths': s3_paths,
        'attachment_count': len([p for p in s3_paths if 'attachments/' in p]),
        'uploaded': uploaded,
        'archived': archived,
        'deleted': deleted
    }
    
    if dry_run:
        logger.info("  [DRY RUN] Would add to index: %s", INDEX_FILE)
    else:
        with open(INDEX_FILE, 'a') as f:
            f.write(json.dumps(index_entry) + '\n')

def archive_email(service, msg_id, dry_run=False):
    """Move email to archive (remove from inbox)"""
    if dry_run:
        logger.info("  [DRY RUN] Would archive email in Gmail")
        return
    
    service.users().messages().modify(
        userId='me',
        id=msg_id,
        body={'removeLabelIds': ['INBOX']}
    ).execute()

def delete_email(service, msg_id, dry_run=False):
    """Permanently delete email from Gmail
    
    WARNING: This is a permanent deletion. The email will be moved to trash
    and will be permanently deleted after 30 days (or immediately if trash is emptied).
    """
    if dry_run:
        logger.warning("  [DRY RUN] Would PERMANENTLY DELETE email from Gmail")
        return
    
    logger.warning("  ⚠ PERMANENTLY DELETING email from Gmail")
    service.users().messages().trash(
        userId='me',
        id=msg_id
    ).execute()

def verify_s3_upload(s3_client, s3_bucket, s3_paths, dry_run=False):
    """Verify that all files were successfully uploaded to S3"""
    if dry_run:
        logger.debug("  [DRY RUN] Would verify S3 upload")
        return True
    
    try:
        for path in s3_paths:
            # Check if object exists in S3
            s3_client.head_object(Bucket=s3_bucket, Key=path)
        logger.debug("  ✓ Verified all %d files exist in S3", len(s3_paths))
        return True
    except Exception as e:
        logger.error("  ✗ S3 verification failed: %s", e)
        return False

def upload_index_to_s3(s3_client, s3_bucket, dry_run=False):
    """Upload the index file to S3 for backup"""
    if not os.path.exists(INDEX_FILE):
        return
    
    index_key = f"index/{INDEX_FILE}"
    if dry_run:
        logger.info("\n[DRY RUN] Would upload index to s3://%s/%s", s3_bucket, index_key)
    else:
        with open(INDEX_FILE, 'rb') as f:
            s3_client.put_object(
                Bucket=s3_bucket,
                Key=index_key,
                Body=f,
                ContentType='application/x-ndjson',
                StorageClass='STANDARD'
            )
        logger.info("\n✓ Uploaded index to s3://%s/%s", s3_bucket, index_key)

def main():
    parser = argparse.ArgumentParser(
        description='Archive large Gmail emails to S3 Glacier Deep Archive with attachments'
    )
    parser.add_argument(
        '--s3-bucket',
        required=True,
        help='S3 bucket name for storing archived emails (required)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Run in dry-run mode without making any changes'
    )
    parser.add_argument(
        '--size-mb',
        type=int,
        default=10,
        help='Minimum total email size in MB (default: 10)'
    )
    parser.add_argument(
        '--older-than-years',
        type=int,
        default=1,
        help='Only process emails older than N years (default: 1)'
    )
    parser.add_argument(
        '--archive-gmail',
        action='store_true',
        help='Archive emails in Gmail after uploading to S3 (removes from inbox but keeps in All Mail)'
    )
    parser.add_argument(
        '--delete-gmail',
        action='store_true',
        help='DANGEROUS: Permanently delete emails from Gmail after uploading to S3 (moves to trash)'
    )
    parser.add_argument(
        '--i-understand-deletion-is-permanent',
        action='store_true',
        help='Required confirmation flag when using --delete-gmail'
    )
    parser.add_argument(
        '--max-emails',
        type=int,
        default=None,
        help='Maximum number of emails to process (for testing)'
    )
    parser.add_argument(
        '--force-reprocess',
        action='store_true',
        help='Force reprocessing of emails already in index (not recommended)'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level (default: INFO)'
    )
    
    args = parser.parse_args()
    
    # Safety check for deletion
    if args.delete_gmail and not args.i_understand_deletion_is_permanent:
        logger.error("=" * 60)
        logger.error("SAFETY CHECK FAILED")
        logger.error("=" * 60)
        logger.error("You are attempting to DELETE emails from Gmail.")
        logger.error("This is a PERMANENT action that cannot be undone.")
        logger.error("")
        logger.error("If you understand the risks and want to proceed, add:")
        logger.error("  --i-understand-deletion-is-permanent")
        logger.error("")
        logger.error("NOTE: Deleted emails go to trash and are permanently")
        logger.error("deleted after 30 days (or sooner if you empty trash).")
        logger.error("=" * 60)
        return
    
    if args.delete_gmail and args.archive_gmail:
        logger.error("Cannot use both --archive-gmail and --delete-gmail together.")
        logger.error("Choose one: archive (keeps in All Mail) or delete (moves to trash).")
        return
    
    # Set log level
    logger.setLevel(getattr(logging, args.log_level))
    
    if args.dry_run:
        logger.info("=" * 60)
        logger.info("RUNNING IN DRY-RUN MODE - No changes will be made")
        logger.info("=" * 60)
    
    if args.delete_gmail:
        logger.warning("=" * 60)
        logger.warning("⚠ DELETION MODE ENABLED ⚠")
        logger.warning("Emails will be PERMANENTLY DELETED after upload")
        logger.warning("=" * 60)
    
    logger.info("S3 Bucket: %s", args.s3_bucket)
    
    # Initialize services
    gmail_service = get_gmail_service()
    s3_client = boto3.client('s3') if not args.dry_run else None
    
    # Load existing index to avoid reprocessing
    if args.force_reprocess:
        logger.warning("--force-reprocess enabled: will reprocess emails already in index")
        processed_emails = {}
    else:
        processed_emails = load_existing_index()
    
    # Search for large emails
    logger.info("Searching for emails larger than %d MB and older than %d year(s)...", 
                args.size_mb, args.older_than_years)
    messages = search_large_emails(
        gmail_service, 
        size_mb=args.size_mb, 
        older_than_years=args.older_than_years
    )
    
    if args.max_emails:
        messages = messages[:args.max_emails]
    
    logger.info("Found %d emails to archive", len(messages))
    
    if len(messages) == 0:
        logger.info("No emails to process. Exiting.")
        return
    
    # Process each email
    total_size_mb = 0
    total_attachments = 0
    skipped_count = 0
    already_processed_count = 0
    
    for i, msg in enumerate(messages):
        try:
            msg_id = msg['id']
            
            # Check if already processed and determine what actions are needed
            previous_status = processed_emails.get(msg_id)
            
            if previous_status:
                # Email was processed before - check what needs to be done
                if previous_status['deleted']:
                    logger.info("[%d/%d] ⊘ Skipping %s - already deleted from Gmail", 
                               i+1, len(messages), msg_id)
                    already_processed_count += 1
                    continue
                
                # Determine if we need to do anything
                needs_upload = not previous_status['uploaded']
                needs_archive = args.archive_gmail and not previous_status['archived']
                needs_delete = args.delete_gmail and not previous_status['deleted']
                
                # If upload was done, verify S3 objects still exist
                if previous_status['uploaded'] and not needs_upload:
                    if not args.dry_run:
                        s3_exists, size_matches = check_s3_objects_exist(
                            s3_client, 
                            args.s3_bucket, 
                            previous_status['s3_paths'],
                            previous_status['size_bytes']
                        )
                        if not s3_exists:
                            logger.warning("[%d/%d] ⚠ %s - S3 objects missing, will re-upload", 
                                         i+1, len(messages), msg_id)
                            needs_upload = True
                        elif not size_matches:
                            logger.warning("[%d/%d] ⚠ %s - S3 size mismatch, will re-upload", 
                                         i+1, len(messages), msg_id)
                            needs_upload = True
                        else:
                            logger.debug("[%d/%d] ✓ %s - S3 objects verified", 
                                        i+1, len(messages), msg_id)
                
                # If nothing needs to be done, skip
                if not needs_upload and not needs_archive and not needs_delete:
                    logger.info("[%d/%d] ⊘ Skipping %s - already fully processed", 
                               i+1, len(messages), msg_id)
                    already_processed_count += 1
                    continue
                
                # Log what actions will be taken
                actions = []
                if needs_upload:
                    actions.append("upload")
                if needs_archive:
                    actions.append("archive")
                if needs_delete:
                    actions.append("delete")
                logger.info("[%d/%d] Processing %s - actions needed: %s", 
                           i+1, len(messages), msg_id, ", ".join(actions))
            else:
                logger.info("[%d/%d] Processing: %s", i+1, len(messages), msg_id)
                needs_upload = True
                needs_archive = args.archive_gmail
                needs_delete = args.delete_gmail
            
            # Get full email data
            email_data = get_email_data(gmail_service, msg_id)
            
            # Parse metadata
            metadata = parse_email_metadata(email_data)
            
            subject_truncated = metadata['subject'][:60]
            if len(metadata['subject']) > 60:
                subject_truncated += '...'
            
            logger.info("  Subject: %s", subject_truncated)
            logger.info("  From: %s", metadata['from'])
            logger.info("  Date: %s", metadata['date'])
            logger.info("  Total email size: %.2f MB", metadata['size_mb'])
            
            # Extract attachments
            parts = email_data.get('payload', {}).get('parts', [])
            attachments = extract_attachments(gmail_service, msg_id, parts, dry_run=args.dry_run)
            
            # Calculate total attachment size
            attachments_size_mb = calculate_attachments_size(attachments)
            logger.info("  Attachments: %d (total size: %.2f MB)", len(attachments), attachments_size_mb)
            
            # Check if total email size meets threshold
            if metadata['size_mb'] < args.size_mb:
                logger.info("  ⊘ Skipping: total email size (%.2f MB) below threshold (%d MB)", 
                           metadata['size_mb'], args.size_mb)
                skipped_count += 1
                continue
            
            total_size_mb += metadata['size_mb']
            total_attachments += len(attachments)
            
            # Track what was actually done (for index)
            upload_done = False
            archive_done = False
            delete_done = False
            s3_paths = []
            
            # Upload to S3 if needed
            if needs_upload:
                s3_paths = upload_to_s3(s3_client, email_data, msg_id, attachments, args.s3_bucket, dry_run=args.dry_run)
                if not args.dry_run:
                    logger.info("  ✓ Uploaded %d file(s) to S3", len(s3_paths))
                    upload_done = True
                    
                    # Verify S3 upload before any Gmail modifications
                    upload_verified = verify_s3_upload(s3_client, args.s3_bucket, s3_paths, dry_run=args.dry_run)
                    if not upload_verified:
                        logger.error("  ✗ Skipping Gmail operations - S3 upload verification failed")
                        continue
                else:
                    upload_done = True  # For dry-run tracking
            else:
                # Use previous S3 paths
                s3_paths = previous_status.get('s3_paths', [])
                upload_done = True
                logger.info("  ⊘ Upload skipped - already in S3")
            
            # Delete or archive the email from Gmail if needed
            if needs_delete:
                delete_email(gmail_service, msg_id, dry_run=args.dry_run)
                if not args.dry_run:
                    logger.info("  ✓ Deleted from Gmail")
                    delete_done = True
                else:
                    delete_done = True  # For dry-run tracking
            elif needs_archive:
                archive_email(gmail_service, msg_id, dry_run=args.dry_run)
                if not args.dry_run:
                    logger.info("  ✓ Archived in Gmail")
                    archive_done = True
                else:
                    archive_done = True  # For dry-run tracking
            
            # Add to index with status flags
            add_to_index(
                msg_id, 
                metadata, 
                s3_paths, 
                uploaded=upload_done,
                archived=archive_done or (previous_status and previous_status['archived']),
                deleted=delete_done or (previous_status and previous_status['deleted']),
                dry_run=args.dry_run
            )
            
        except Exception as e:
            logger.error("  ✗ Error processing %s: %s", msg_id, e)
            if logger.isEnabledFor(logging.DEBUG):
                logger.exception("Full traceback:")
            continue
    
    # Upload index to S3
    if not args.dry_run:
        upload_index_to_s3(s3_client, args.s3_bucket, dry_run=args.dry_run)
    
    # Summary
    logger.info("=" * 60)
    logger.info("SUMMARY")
    logger.info("=" * 60)
    logger.info("Total emails found: %d", len(messages))
    logger.info("Already processed (skipped): %d", already_processed_count)
    logger.info("Below attachment threshold (skipped): %d", skipped_count)
    logger.info("Newly archived: %d", len(messages) - skipped_count - already_processed_count)
    logger.info("Total attachments: %d", total_attachments)
    logger.info("Total size: %.2f MB (%.2f GB)", total_size_mb, total_size_mb/1024)
    
    if not args.dry_run:
        monthly_cost = (total_size_mb / 1024) * 0.00099
        logger.info("Estimated S3 Glacier Deep Archive cost: $%.4f/month", monthly_cost)
        logger.info("\nIndex file saved to: %s", INDEX_FILE)
        logger.info("To search the index, use: grep 'search_term' %s", INDEX_FILE)
    else:
        logger.info("\n[DRY RUN] No actual changes were made.")
        logger.info("Run without --dry-run to actually archive emails.")

if __name__ == '__main__':
    main()