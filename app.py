import streamlit as st
import json
import logging
from datetime import datetime
import pandas as pd
import subprocess
import os
from pathlib import Path

# Load environment variables from .env file
def load_env():
    """Load S3_BUCKET from .env file"""
    env_file = Path(__file__).parent / '.env'
    bucket_name = None
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('S3_BUCKET=') and '=' in line:
                    bucket_name = line.split('=', 1)[1].strip()
    return bucket_name

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

INDEX_FILE = 'email_index.jsonl'
S3_BUCKET = load_env() or 'iwashu-gmail-backup'

def load_index():
    """Load all entries from the index"""
    entries = []
    try:
        with open(INDEX_FILE, 'r') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    entries.append(json.loads(line.strip()))
                except json.JSONDecodeError as e:
                    logger.warning("Skipping invalid JSON at line %d: %s", line_num, e)
        logger.debug("Loaded %d entries from index", len(entries))
    except FileNotFoundError:
        logger.error("Index file '%s' not found.", INDEX_FILE)
        return []
    return entries

def search_index(entries, query=None, from_addr=None, to_addr=None,
                 date_from=None, date_to=None, min_size_mb=None,
                 has_attachments=False):
    """Search the index with various filters"""
    results = entries

    # Text search in subject, from, to
    if query:
        query_lower = query.lower()
        results = [e for e in results if
                   query_lower in e.get('subject', '').lower() or
                   query_lower in e.get('from', '').lower() or
                   query_lower in e.get('to', '').lower()]
        logger.debug("After query filter: %d results", len(results))

    # From address filter
    if from_addr:
        from_lower = from_addr.lower()
        results = [e for e in results if from_lower in e.get('from', '').lower()]
        logger.debug("After from_addr filter: %d results", len(results))

    # To address filter
    if to_addr:
        to_lower = to_addr.lower()
        results = [e for e in results if to_lower in e.get('to', '').lower()]
        logger.debug("After to_addr filter: %d results", len(results))

    # Date range filter
    if date_from:
        results = [e for e in results if e.get('date', '')[:10] >= date_from]
        logger.debug("After date_from filter: %d results", len(results))
    if date_to:
        results = [e for e in results if e.get('date', '')[:10] <= date_to]
        logger.debug("After date_to filter: %d results", len(results))

    # Size filter
    if min_size_mb:
        results = [e for e in results if e.get('size_mb', 0) >= min_size_mb]
        logger.debug("After min_size_mb filter: %d results", len(results))

    # Attachment filter
    if has_attachments:
        results = [e for e in results if e.get('attachment_count', 0) > 0]
        logger.debug("After has_attachments filter: %d results", len(results))

    return results


def restore_from_glacier(email_entry):
    """Initiate S3 Glacier Deep Archive restoration for an email"""
    msg_id = email_entry['msg_id']

    # Get the email.json path (not attachments)
    s3_paths = email_entry.get('s3_paths', [])
    email_path = None
    for p in s3_paths:
        if p.endswith('/email.json'):
            email_path = p
            break

    if not email_path:
        return False, "Could not find email.json path"

    full_key = f"{S3_BUCKET}/{email_path}"

    try:
        # Initiate restoration (12-48 hours for Glacier Deep Archive)
        cmd = [
            'aws', 's3api', 'restore-object',
            '--bucket', S3_BUCKET,
            '--key', email_path,
            '--restore-request', 'Days=1,GlacierJobParameters={Tier=Bulk}'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            return True, f"Restore initiated for {email_path}. Will be available in 12-48 hours."
        else:
            return False, f"AWS error: {result.stderr}"

    except FileNotFoundError:
        return False, "AWS CLI not found. Please install it first."
    except Exception as e:
        return False, str(e)

def main():
    st.title("Gmail S3 Archiver Search")

    entries = load_index()
    if not entries:
        st.error("Index file 'email_index.jsonl' not found.")
        st.stop()

    # Sidebar for filters
    st.sidebar.header("Search Filters")

    with st.sidebar.form("search_form"):
        query = st.text_input("Query", placeholder="Search in subject, from, or to")
        from_addr = st.text_input("From", placeholder="Filter by sender")
        to_addr = st.text_input("To", placeholder="Filter by recipient")
        date_from = st.date_input("Date From", value=None)
        date_to = st.date_input("Date To", value=None)
        min_size_mb = st.number_input("Min Size (MB)", min_value=0.0, step=0.1, value=0.0)
        has_attachments = st.checkbox("Has Attachments")

        submitted = st.form_submit_button("Search")

    if submitted:
        # Convert dates to string
        df_str = date_from.strftime("%Y-%m-%d") if date_from else None
        dt_str = date_to.strftime("%Y-%m-%d") if date_to else None

        results = search_index(
            entries,
            query=query if query else None,
            from_addr=from_addr if from_addr else None,
            to_addr=to_addr if to_addr else None,
            date_from=df_str,
            date_to=dt_str,
            min_size_mb=min_size_mb if min_size_mb > 0 else None,
            has_attachments=has_attachments
        )

        if results:
            st.session_state['search_results'] = results
        else:
            st.session_state['search_results'] = []

    results = st.session_state.get('search_results')
    if results is not None:
        if results:
            # Prepare data for dataframe with full message ID in expandable section
            table_data = []
            for entry in results:
                msg_id_short = entry['msg_id'][:12] + '...' if len(entry['msg_id']) > 12 else entry['msg_id']
                subject_display = entry['subject'][:40] + ('...' if len(entry['subject']) > 40 else '')
                from_display = entry['from'][:30] + ('...' if len(entry['from']) > 30 else '')
                date_display = entry['date'][:10] if entry.get('date') else ''
                size_display = f"{entry['size_mb']:.2f}"
                attachments = entry['attachment_count']

                table_data.append({
                    'Message ID': msg_id_short,
                    'Subject': subject_display,
                    'From': from_display,
                    'Date': date_display,
                    'Size (MB)': size_display,
                    'Attachments': attachments
                })

            df = pd.DataFrame(table_data)
            selection = st.dataframe(
                df,
                use_container_width=True,
                on_select="rerun",
                selection_mode="multi-row",
            )

            # Add restore section below the table
            st.subheader("Restore from Glacier Deep Archive")
            st.warning("⚠️ Restoration takes 12-48 hours. You will be billed for retrieval.")

            selected_rows = selection.selection.rows
            if selected_rows:
                st.write(f"**{len(selected_rows)} email(s) selected**")
                if st.button("🔄 Restore selected emails from Glacier", use_container_width=True):
                    for idx in selected_rows:
                        entry = results[idx]
                        with st.spinner(f"Initiating restore for: {entry.get('subject', 'No subject')}..."):
                            success, message = restore_from_glacier(entry)
                        if success:
                            st.success(f"{entry.get('subject', 'No subject')}: {message}")
                        else:
                            st.error(f"{entry.get('subject', 'No subject')}: {message}")
            else:
                st.info("Select rows in the table above to restore them.")
        else:
            st.info("No results found.")

    # Archive Statistics
    st.header("Archive Statistics")
    total_emails = len(entries)
    if total_emails > 0:
        total_size_mb = sum(e.get('size_mb', 0) for e in entries)
        total_attachments = sum(e.get('attachment_count', 0) for e in entries)
        emails_with_attachments = sum(1 for e in entries if e.get('attachment_count', 0) > 0)
        avg_size_mb = total_size_mb / total_emails

        st.write(f"Total emails archived: {total_emails}")
        st.write(f"Total size: {total_size_mb:.2f} MB ({total_size_mb/1024:.2f} GB)")
        st.write(f"Total attachments: {total_attachments}")
        st.write(f"Emails with attachments: {emails_with_attachments}")
        st.write(f"Average email size: {avg_size_mb:.2f} MB")

        monthly_cost = (total_size_mb / 1024) * 0.00099
        st.write(f"Estimated monthly S3 cost: ${monthly_cost:.4f}")
    else:
        st.info("No emails in archive yet.")

if __name__ == '__main__':
    main()