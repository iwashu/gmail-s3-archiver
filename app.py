import streamlit as st
import json
import logging
from datetime import datetime
import pandas as pd

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

INDEX_FILE = 'email_index.jsonl'

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
        results = [e for e in results if e.get('date', '') >= date_from]
        logger.debug("After date_from filter: %d results", len(results))
    if date_to:
        results = [e for e in results if e.get('date', '') <= date_to]
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

def main():
    st.title("Gmail S3 Archiver Search")

    entries = load_index()
    if not entries:
        st.error("Index file 'email_index.jsonl' not found.")
        st.stop()

    # Sidebar for filters
    st.sidebar.header("Search Filters")
    query = st.sidebar.text_input("Query", placeholder="Search in subject, from, or to")
    from_addr = st.sidebar.text_input("From", placeholder="Filter by sender")
    to_addr = st.sidebar.text_input("To", placeholder="Filter by recipient")
    date_from = st.sidebar.date_input("Date From", value=None)
    date_to = st.sidebar.date_input("Date To", value=None)
    min_size_mb = st.sidebar.number_input("Min Size (MB)", min_value=0.0, step=0.1, value=0.0)
    has_attachments = st.sidebar.checkbox("Has Attachments")

    if st.sidebar.button("Search"):
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
            # Prepare data for dataframe
            table_data = []
            for entry in results:
                msg_id_short = entry['msg_id'][:12] + '...' if len(entry['msg_id']) > 12 else entry['msg_id']
                subject_display = entry['subject'][:40] + ('...' if len(entry['subject']) > 40 else '')
                from_display = entry['from'][:30] + ('...' if len(entry['from']) > 30 else '')
                date_display = entry['date'][:10] if entry.get('date') else ''
                size_display = f"{entry['size_mb']:.1f}"
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
            st.dataframe(df, use_container_width=True)
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