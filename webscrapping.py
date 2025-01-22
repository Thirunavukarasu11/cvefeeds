import requests
from bs4 import BeautifulSoup
import re
import html
import sqlite3  # Use sqlite3 instead of pymysql
import warnings
from cryptography.hazmat.backends import default_backend
from cryptography.utils import CryptographyDeprecationWarning
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Database file location (you can specify the path here)
DB_FILE = 'cve_database.db'  # SQLite database file

def get_db_connection():
    """Establish SQLite database connection."""
    try:
        # Return SQLite connection to the database file
        conn = sqlite3.connect(DB_FILE)
        return conn
    except sqlite3.Error as e:
        print(f"Error connecting to SQLite database: {e}")
        return None

def create_cve_table():
    """Create the CVE table if it doesn't exist."""
    conn = get_db_connection()
    if conn is None:
        return False

    try:
        with conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS ca_cve (
                                cve_number TEXT PRIMARY KEY,
                                cve_name TEXT,
                                cve_description TEXT,
                                cve_pubdate TEXT,
                                cve_link TEXT,
                                cve_severity TEXT
                            )''')
        print("CVE table is ready.")
        return True
    except sqlite3.Error as e:
        print(f"Error creating table: {e}")
        return False
    finally:
        conn.close()

def insert_cve_to_db(cve_details):
    """Insert CVE details into the SQLite database."""
    conn = get_db_connection()
    if conn is None:
        return False

    try:
        with conn:
            sql = """INSERT INTO ca_cve (cve_number, cve_name, cve_description, cve_pubdate, cve_link, cve_severity) 
                     VALUES (?, ?, ?, ?, ?, ?)"""
            conn.execute(sql, (
                cve_details['cve_number'],
                cve_details['cve_name'],
                cve_details['cve_description'],
                cve_details['cve_pubdate'],
                cve_details['cve_link'],
                cve_details['cve_severity']
            ))
            print(f"Inserted CVE: {cve_details['cve_number']}")
            return True
    except sqlite3.Error as e:
        print(f"Error inserting CVE into SQLite database: {e}")
        return False
    finally:
        conn.close()

def cve_exists(cve_number):
    """Check if a CVE already exists in the SQLite database."""
    conn = get_db_connection()
    if conn is None:
        return False

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM ca_cve WHERE cve_number = ?", (cve_number,))
        return cursor.fetchone() is not None
    except sqlite3.Error as e:
        print(f"Error checking CVE existence: {e}")
        return False
    finally:
        conn.close()

def fetch_and_process_cve():
    """Fetch CVE data from the RSS feed and process it."""
    url = "https://cvefeed.io/rssfeed/severity/high.xml"

    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'lxml-xml')
        items = soup.find_all('item')

        for item in items:
            title = item.find('title').text
            link = item.find('link').text
            pub_date = item.find('pubDate').text

            cve_number_match = re.search(r'CVE-\d{4}-\d{4,}', title)
            cve_number = cve_number_match.group() if cve_number_match else 'N/A'

            if cve_exists(cve_number):
                print(f"{cve_number} already exists. Skipping.")
                continue

            # Fetch detailed page for description and severity
            cve_page_response = requests.get(link)
            cve_page_response.raise_for_status()
            cve_page_soup = BeautifulSoup(cve_page_response.content, 'html.parser')

            # Extract description and severity
            description_cell = cve_page_soup.find('td', string='Description')
            if description_cell:
                clean_description = description_cell.find_next_sibling('td').text.strip()
                clean_description = html.unescape(clean_description).replace('\n', ' ').strip()
            else:
                clean_description = 'Description not available.'

            severity_match = re.search(r'Severity:\s*(\d+(\.\d+)?)\s*\|\s*(\w+)', clean_description)
            severity = severity_match.group(1) if severity_match else None

            cve_details = {
                'cve_number': cve_number,
                'cve_name': title.split('- ', 1)[1] if '- ' in title else 'N/A',
                'cve_description': clean_description,
                'cve_pubdate': pub_date,
                'cve_link': link,
                'cve_severity': severity
            }

            if insert_cve_to_db(cve_details):
                print(f"Processed CVE: {cve_number}")

    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVE feed: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

# Suppress the deprecated warning more effectively
warnings.simplefilter("ignore", CryptographyDeprecationWarning)

# Initialize database and create table if it doesn't exist
create_cve_table()

# Start processing CVEs
fetch_and_process_cve()


# sqlite3 cve_database.db
# SELECT * FROM ca_cve;
