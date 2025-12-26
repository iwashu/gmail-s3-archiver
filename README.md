# Gmail to S3 Glacier Archiver

Archive large Gmail emails with attachments to AWS S3 Glacier Deep Archive with a searchable index.

## Features

✅ **Attachment-based filtering** - Archives emails based on total attachment size (not individual email size)  
✅ **Attachment extraction** - Automatically extracts and uploads all attachments separately  
✅ **Search index** - Creates a local searchable index (JSONL format) of all archived emails  
✅ **Glacier Deep Archive** - Uses cheapest S3 storage class (~$1/TB/month)  
✅ **Dry run mode** - Test before making changes  
✅ **Flexible filtering** - Filter by size, age, sender, etc.  
✅ **Built with uv** - Fast, modern Python package management

## How It Works

The script uses a two-step filtering process:

1. **Initial Gmail Search**: Searches for emails with total size > threshold (default 10MB) that are older than specified years
2. **Attachment Size Check**: For each email found, calculates the total size of all attachments combined
3. **Archive Decision**: Only archives emails where attachment total meets or exceeds the threshold

**Example**: An email with 5 attachments of 3MB each (15MB total) will be archived, even if the email body is small. This helps you identify and backup emails that are consuming space primarily due to attachments.

## Setup

### 1. Install uv (if not already installed)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Create project and install dependencies

```bash
mkdir gmail-s3-archiver
cd gmail-s3-archiver

# Initialize project
uv init

# Add dependencies
uv add google-auth-oauthlib google-auth-httplib2 google-api-python-client boto3

# For the search utility
uv add tabulate
```

### 3. Setup Gmail API (Detailed Instructions)

#### Step 1: Go to Google Cloud Console
Visit: https://console.cloud.google.com

#### Step 2: Create a New Project
- Click on the project dropdown at the top
- Click **"New Project"**
- Give it a name like "Gmail S3 Archiver"
- Click **"Create"**

#### Step 3: Enable Gmail API
- Make sure your new project is selected
- Go to **"APIs & Services"** → **"Library"** (in the left sidebar)
- Search for **"Gmail API"**
- Click on it and press **"Enable"**

#### Step 4: Configure OAuth Consent Screen
- Go to **"APIs & Services"** → **"OAuth consent screen"**
- Choose **"External"** (unless you have a Google Workspace account)
- Click **"Create"**
- Fill in the required fields:
  - **App name**: "Gmail S3 Archiver" (or whatever you like)
  - **User support email**: Your email
  - **Developer contact email**: Your email
- Click **"Save and Continue"**
- On the **Scopes** page, click **"Save and Continue"**
- On **Test users**, click **"Add Users"** and **add your Gmail address** (IMPORTANT!)
- Click **"Save and Continue"**

#### Step 5: Create OAuth 2.0 Credentials
- Go to **"APIs & Services"** → **"Credentials"**
- Click **"+ Create Credentials"** at the top
- Select **"OAuth client ID"**
- Choose **Application type**: **"Desktop app"**
- Give it a name like "Gmail Archiver Desktop"
- Click **"Create"**

#### Step 6: Download credentials.json
- After creation, a dialog will appear
- Click **"Download JSON"**
- Rename it to `credentials.json`
- Place it in your project directory

#### Step 7: First Run Authentication
When you run the script for the first time:
```bash
uv run python gmail_to_s3.py --dry-run
```

- Your browser will open automatically
- Sign in with your Gmail account
- You'll see a warning **"Google hasn't verified this app"**
- Click **"Advanced"** → **"Go to Gmail S3 Archiver (unsafe)"**
- Click **"Allow"** to grant permissions
- The script will create `token.pickle` to store your auth token

**Note:** If you see "The app is blocked" error, make sure you added your email as a test user in Step 4!

### 4. Configure AWS

```bash
# Set up AWS credentials
aws configure

# Create S3 bucket (replace with your desired bucket name)
aws s3 mb s3://my-gmail-archive-bucket
```

**Note:** You'll pass the bucket name as a command-line argument when running the script.

### 5. Add the scripts

Save the three artifacts:
- `gmail_to_s3.py` - Main archiver script
- `search_index.py` - Search utility
- Make them executable: `chmod +x *.py`

## Usage

### Archive Emails

**Note:** `--s3-bucket` is required for all commands.

```bash
# Dry run first (recommended)
uv run python gmail_to_s3.py --s3-bucket my-gmail-archive-bucket --dry-run

# Dry run with custom filters (emails with 20MB+ in attachments, older than 2 years)
uv run python gmail_to_s3.py --s3-bucket my-gmail-archive-bucket --dry-run --size-mb 20 --older-than-years 2

# Actually archive (default: emails with 10MB+ attachments, older than 1 year)
uv run python gmail_to_s3.py --s3-bucket my-gmail-archive-bucket

# Archive emails in Gmail (removes from inbox, keeps in All Mail)
uv run python gmail_to_s3.py --s3-bucket my-gmail-archive-bucket --archive-gmail

# Process only emails with very large attachments (50MB+)
uv run python gmail_to_s3.py --s3-bucket my-gmail-archive-bucket --size-mb 50 --older-than-years 3

# Test with limited number of emails
uv run python gmail_to_s3.py --s3-bucket my-gmail-archive-bucket --max-emails 5 --dry-run

# Enable debug logging to see more details
uv run python gmail_to_s3.py --s3-bucket my-gmail-archive-bucket --dry-run --log-level DEBUG
```

**Note**: The `--size-mb` parameter filters based on the total size of attachments in each email, not the entire email size.

### ⚠️ DANGEROUS: Deleting Emails

**WARNING: This is a permanent deletion. Only use if you fully understand the risks.**

The script can automatically delete emails from Gmail after successful S3 upload, but this requires explicit confirmation:

```bash
# Test deletion in dry-run mode first (ALWAYS DO THIS FIRST)
uv run python gmail_to_s3.py \
  --s3-bucket my-gmail-archive-bucket \
  --delete-gmail \
  --i-understand-deletion-is-permanent \
  --dry-run \
  --max-emails 5

# Actually delete emails (DANGEROUS - be very careful)
uv run python gmail_to_s3.py \
  --s3-bucket my-gmail-archive-bucket \
  --delete-gmail \
  --i-understand-deletion-is-permanent
```

**Important Notes on Deletion:**
- Deleted emails are moved to Gmail's Trash folder
- Emails in Trash are permanently deleted after 30 days
- You can empty Trash manually to delete immediately
- The script verifies S3 upload succeeded before deleting
- **Always test with `--dry-run` and `--max-emails 5` first**
- Cannot use both `--archive-gmail` and `--delete-gmail` together
- Requires the `--i-understand-deletion-is-permanent` flag as a safety measure

### Search Archive

```bash
# Show archive statistics
uv run python search_index.py --stats

# Search for specific term
uv run python search_index.py --query "invoice"

# Search by sender
uv run python search_index.py --from john@example.com

# Find large emails with attachments
uv run python search_index.py --min-size 50 --has-attachments

# Detailed view with S3 paths
uv run python search_index.py --query "report" --verbose

# Complex search
uv run python search_index.py --from "@company.com" --min-size 20 --has-attachments
```

## S3 Structure

```
s3://your-gmail-archive-bucket/
├── emails/
│   └── 2023/
│       └── 06/
│           └── msg_abc123/
│               ├── email.json
│               └── attachments/
│                   ├── document.pdf
│                   └── image.jpg
└── index/
    └── email_index.jsonl
```

## Index Format

The index is stored as JSONL (one JSON object per line) for efficient searching:

```json
{
  "msg_id": "abc123",
  "timestamp": "2024-12-26T10:30:00",
  "subject": "Q3 Financial Report",
  "from": "finance@company.com",
  "to": "team@company.com",
  "date": "2023-06-15T09:00:00",
  "size_mb": 45.2,
  "labels": ["INBOX", "IMPORTANT"],
  "s3_paths": [
    "emails/2023/06/abc123/email.json",
    "emails/2023/06/abc123/attachments/report.pdf"
  ],
  "attachment_count": 1
}
```

## Costs

### S3 Glacier Deep Archive
- **Storage**: $0.00099/GB/month (~$1/TB/month)
- **Minimum storage duration**: 180 days
- **Retrieval time**: 12-48 hours
- **Retrieval cost**: ~$0.02/GB

### Example
For 100GB of emails:
- Monthly cost: ~$0.10
- Annual cost: ~$1.20

### Gmail API
- Free up to 1 billion quota units/day (more than enough)

## Retrieving Archived Emails

To retrieve an email from Glacier Deep Archive:

```bash
# 1. Initiate restoration (takes 12-48 hours)
aws s3api restore-object \
  --bucket my-gmail-archive-bucket \
  --key emails/2023/06/abc123/email.json \
  --restore-request Days=1,GlacierJobParameters={Tier=Bulk}

# 2. After restoration completes, download
aws s3 cp s3://my-gmail-archive-bucket/emails/2023/06/abc123/email.json ./
```

## Automation

### Run weekly with cron

```bash
# Edit crontab
crontab -e

# Add line to run every Sunday at 2 AM (replace with your bucket name)
0 2 * * 0 cd /path/to/gmail-s3-archiver && /home/user/.cargo/bin/uv run python gmail_to_s3.py --s3-bucket my-gmail-archive-bucket --archive-gmail
```

### Run on AWS Lambda (for serverless)

1. Package the code with dependencies
2. Set up EventBridge rule for scheduling
3. Configure Lambda with appropriate IAM roles
4. Store `token.pickle` in S3 or use Lambda environment variables

## Tips

1. **Start with dry run** - Always test with `--dry-run` first
2. **Test with `--max-emails 5`** - Verify everything works with a small batch
3. **Backup the index** - The index file is uploaded to S3 automatically
4. **Monitor costs** - Use AWS Cost Explorer to track S3 costs
5. **Consider lifecycle policies** - Archive the index to Glacier after 30 days
6. **Regular searches** - Keep the index file locally for quick searches

## Troubleshooting

**"The app is blocked because it hasn't been verified"**
- Make sure you added your email address as a test user in OAuth consent screen (Step 4)
- Click "Advanced" → "Go to [app name] (unsafe)" - this is safe for apps YOU created

**Authentication error**: Delete `token.pickle` and re-authenticate  
**S3 permission denied**: Check IAM role has PutObject permission  
**Gmail API quota exceeded**: Wait 24 hours, quota resets daily  
**Large attachments failing**: Increase timeout in boto3 client  
**Emails not being archived**: Check if attachment size meets threshold with `--log-level DEBUG`

## Security Notes

- `credentials.json` - Contains OAuth client secrets, don't commit
- `token.pickle` - Contains access tokens, don't commit  
- Add both to `.gitignore`
- Consider encrypting S3 bucket with KMS

## License

MIT - Feel free to modify and use as needed!
