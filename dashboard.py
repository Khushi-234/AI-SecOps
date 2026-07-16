import os
import psycopg2
from dotenv import load_dotenv

# Ensure environment variables are loaded
load_dotenv()

def run():
    try:
        # Establish a network connection using environment variables
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            dbname=os.getenv("DB_NAME")
        )
        cursor = conn.cursor()
        
    except psycopg2.OperationalError as e:
        print("Error: Database connection failed. Ensure PostgreSQL is running and credentials match your .env configuration.")
        print(f"Details: {e}")
        return

    try:
        # Fetch the latest scan record
        cursor.execute("SELECT scan_id, timestamp, total_tests, failed_tests, avg_risk_score, status FROM scans ORDER BY scan_id DESC LIMIT 1")
        latest = cursor.fetchone()
        
        if not latest:
            print("⚠️ No scans found inside the 'security_log' database.")
            return

        print("\n" + "="*70)
        print(" 🛡️  AI-SECOPS ASSESSMENT FRAMEWORK - LOG TERMINAL")
        print("="*70)
        print(f" LATEST RUN: #{latest[0]} | TIMESTAMP: {latest[1]}")
        print(f" AUDIT RESULT: {latest[5]}")
        print(f" STATUS: {latest[3]} Flaws Found out of {latest[2]} Injection Attempts")
        print(f" AVERAGE FRAMEWORK RISK INDEX: {latest[4]} / 10.0")
        print("="*70)

        # Swapped SQLite '?' with PostgreSQL '%s' parameter syntax
        cursor.execute(
            "SELECT category, severity, payload, output, status, risk_score, recommendation FROM scan_results WHERE scan_id = %s", 
            (latest[0],)
        )
        results = cursor.fetchall()

        print("\n 🔍 DETAILED THREAT VECTOR BREAKDOWN:")
        print("-" * 70)
        for idx, row in enumerate(results, 1):
            print(f" [{idx}] VULNERABILITY STATUS: [{row[4]}]")
            print(f"     • Threat Class:    {row[0]} (Severity: {row[1]})")
            print(f"     • Calculated Risk: {row[5]} / 10.0")
            print(f"     • Attack Payload:  \"{row[2]}\"")
            print(f"     • Target Output:   \"{row[3]}\"")
            print(f"     • Fix Guidance:    {row[6]}")
            print("-" * 70)
            
    except Exception as e:
        print(f"Error executing terminal data query: {e}")
        
    finally:
        # Guarantee resources get closed cleanly
        cursor.close()
        conn.close()

if __name__ == "__main__":
    run()