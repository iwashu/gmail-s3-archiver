#!/usr/bin/env python3
"""
Search utility for the email archive index
"""
import json
import argparse
import logging
from datetime import datetime
from tabulate import tabulate

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

def format_results(results, verbose=False):
    """Format search results for display"""
    if not results:
        logger.info("No results found.")
        return
    
    logger.info("\nFound %d email(s):", len(results))
    
    if verbose:
        # Detailed view
        for i, entry in enumerate(results, 1):
            logger.info("[%d] %s", i, '-' * 60)
            logger.info("Message ID: %s", entry['msg_id'])
            logger.info("Subject: %s", entry['subject'])
            logger.info("From: %s", entry['from'])
            logger.info("To: %s", entry['to'])
            logger.info("Date: %s", entry['date'])
            logger.info("Size: %.2f MB", entry['size_mb'])
            logger.info("Attachments: %d", entry['attachment_count'])
            logger.info("S3 Paths:")
            for path in entry['s3_paths']:
                logger.info("  - %s", path)
            logger.info("")
    else:
        # Table view
        table_data = []
        for entry in results:
            msg_id_short = entry['msg_id'][:12] + '...'
            
            subject = entry['subject']
            subject_display = subject[:40] + ('...' if len(subject) > 40 else '')
            
            from_addr = entry['from']
            from_display = from_addr[:30] + ('...' if len(from_addr) > 30 else '')
            
            date_display = entry['date'][:10]
            
            table_data.append([
                msg_id_short,
                subject_display,
                from_display,
                date_display,
                f"{entry['size_mb']:.1f}",
                entry['attachment_count']
            ])
        
        headers = ['Message ID', 'Subject', 'From', 'Date', 'Size (MB)', 'Attachments']
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
        logger.info("\nUse --verbose for full details and S3 paths")

def show_stats(entries):
    """Show statistics about the archive"""
    total_emails = len(entries)
    
    if total_emails == 0:
        logger.info("No emails in archive yet.")
        return
    
    total_size_mb = sum(e.get('size_mb', 0) for e in entries)
    total_attachments = sum(e.get('attachment_count', 0) for e in entries)
    emails_with_attachments = sum(1 for e in entries if e.get('attachment_count', 0) > 0)
    avg_size_mb = total_size_mb / total_emails
    
    logger.info("=" * 60)
    logger.info("ARCHIVE STATISTICS")
    logger.info("=" * 60)
    logger.info("Total emails archived: %d", total_emails)
    logger.info("Total size: %.2f MB (%.2f GB)", total_size_mb, total_size_mb/1024)
    logger.info("Total attachments: %d", total_attachments)
    logger.info("Emails with attachments: %d", emails_with_attachments)
    logger.info("Average email size: %.2f MB", avg_size_mb)
    
    # Storage cost estimate
    monthly_cost = (total_size_mb / 1024) * 0.00099
    logger.info("\nEstimated monthly S3 cost: $%.4f", monthly_cost)
    logger.info("=" * 60)

def main():
    parser = argparse.ArgumentParser(
        description='Search the email archive index',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Search for emails containing "invoice"
  python search_index.py --query invoice
  
  # Search emails from a specific sender
  python search_index.py --from john@example.com
  
  # Find large emails with attachments
  python search_index.py --min-size 50 --has-attachments
  
  # Show archive statistics
  python search_index.py --stats
  
  # Detailed view of results
  python search_index.py --query "quarterly report" --verbose
        """
    )
    
    parser.add_argument('--query', '-q', help='Search text in subject, from, or to fields')
    parser.add_argument('--from', dest='from_addr', help='Filter by sender email')
    parser.add_argument('--to', dest='to_addr', help='Filter by recipient email')
    parser.add_argument('--date-from', help='Filter by date from (YYYY-MM-DD)')
    parser.add_argument('--date-to', help='Filter by date to (YYYY-MM-DD)')
    parser.add_argument('--min-size', type=float, help='Minimum email size in MB')
    parser.add_argument('--has-attachments', action='store_true', help='Only show emails with attachments')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed results with S3 paths')
    parser.add_argument('--stats', action='store_true', help='Show archive statistics')
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level (default: INFO)'
    )
    
    args = parser.parse_args()
    
    # Set log level
    logger.setLevel(getattr(logging, args.log_level))
    
    # Load index
    entries = load_index()
    if not entries:
        return
    
    # Show stats if requested
    if args.stats:
        show_stats(entries)
        return
    
    # Search
    logger.debug("Starting search with filters...")
    results = search_index(
        entries,
        query=args.query,
        from_addr=args.from_addr,
        to_addr=args.to_addr,
        date_from=args.date_from,
        date_to=args.date_to,
        min_size_mb=args.min_size,
        has_attachments=args.has_attachments
    )
    
    # Display results
    format_results(results, verbose=args.verbose)

if __name__ == '__main__':
    main()