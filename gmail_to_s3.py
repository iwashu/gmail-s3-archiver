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

def add_to_index(msg_id, metadata, s3_paths, dry_run=False):
    """Add email to search index"""
    index_entry = {
        'msg_id': msg_id,
        'timestamp': datetime.now().isoformat(),
        'subject': metadata['subject'],
        'from': metadata['from'],
        'to': metadata['to'],
        'date': metadata['date_parsed'],
        'size_mb': metadata['size_mb'],
        'labels': metadata['labels'],
        's3_paths': s3_paths,
        'attachment_count': len([p for p in s3_paths if 'attachments/' in p])
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
        help='Minimum email size in MB (default: 10)'
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
        help='Archive emails in Gmail after uploading to S3'
    )
    parser.add_argument(
        '--max-emails',
        type=int,
        default=None,
        help='Maximum number of emails to process (for testing)'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level (default: INFO)'
    )
    
    args = parser.parse_args()
    
    # Set log level
    logger.setLevel(getattr(logging, args.log_level))
    
    if args.dry_run:
        logger.info("=" * 60)
        logger.info("RUNNING IN DRY-RUN MODE - No changes will be made")
        logger.info("=" * 60)
    
    logger.info("S3 Bucket: %s", args.s3_bucket)
    
    # Initialize services
    gmail_service = get_gmail_service()
    s3_client = boto3.client('s3') if not args.dry_run else None
    
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
    
    for i, msg in enumerate(messages):
        try:
            msg_id = msg['id']
            logger.info("[%d/%d] Processing: %s", i+1, len(messages), msg_id)
            
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
            
            # Check if attachment size meets threshold
            if attachments_size_mb < args.size_mb:
                logger.info("  ⊘ Skipping: attachment size (%.2f MB) below threshold (%d MB)", 
                           attachments_size_mb, args.size_mb)
                skipped_count += 1
                continue
            
            total_size_mb += metadata['size_mb']
            total_attachments += len(attachments)
            
            # Upload to S3
            s3_paths = upload_to_s3(s3_client, email_data, msg_id, attachments, args.s3_bucket, dry_run=args.dry_run)
            if not args.dry_run:
                logger.info("  ✓ Uploaded %d file(s) to S3", len(s3_paths))
            
            # Add to index
            add_to_index(msg_id, metadata, s3_paths, dry_run=args.dry_run)
            
            # Optional: Archive the email from Gmail
            if args.archive_gmail:
                archive_email(gmail_service, msg_id, dry_run=args.dry_run)
                if not args.dry_run:
                    logger.info("  ✓ Archived in Gmail")
            
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
    logger.info("Total emails archived: %d", len(messages) - skipped_count)
    logger.info("Total emails skipped: %d", skipped_count)
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