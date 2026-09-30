import os
import psycopg2
from dotenv import load_dotenv

# Ensure environment variables are loaded
load_dotenv()


def run():
    try:
        # Establish PostgreSQL network connection using environment variables
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", "5432"),
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "postgres"),
            dbname=os.getenv("DB_NAME", "aisecops_db"),
        )
        cursor = conn.cursor()

    except psycopg2.OperationalError as e:
        print(
            "❌ Error: Database connection failed. Ensure PostgreSQL is running and credentials match your .env configuration."
        )
        print(f"Details: {e}")
        return

    try:
        # Check if Sprint 12 audit_events table exists
        cursor.execute(
            """
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'audit_events'
            );
            """
        )
        has_audit_events = cursor.fetchone()[0]

        if has_audit_events:
            cursor.execute("SELECT COUNT(*) FROM audit_events;")
            total_count = cursor.fetchone()[0]

            cursor.execute(
                "SELECT event_id, request_id, timestamp, component, event_type, severity, action, status, message "
                "FROM audit_events ORDER BY timestamp DESC LIMIT 10"
            )
            rows = cursor.fetchall()

            print("\n" + "=" * 80)
            print(" 🛡️  AI-SECOPS ASSESSMENT FRAMEWORK — AUDIT LOG TERMINAL")
            print("=" * 80)
            print(f" TOTAL PERSISTED AUDIT EVENTS : {total_count}")
            print(f" DISPLAYING RECENT EVENTS     : {len(rows)}")
            print("=" * 80)

            if not rows:
                print("\n⚠️ No audit records found in 'audit_events' table.")
                return

            print("\n 🔍 RECENT AUDIT EVENT LOGS:")
            print("-" * 80)
            for idx, r in enumerate(rows, 1):
                event_id, req_id, ts, comp, evt_type, sev, act, stat, msg = r
                print(f" [{idx}] Event ID : {event_id} | Request ID: {req_id}")
                print(f"     • Timestamp : {ts}")
                print(f"     • Component : {comp} ({evt_type})")
                print(f"     • Decision  : Status: [{stat}] | Action: [{act}] | Severity: [{sev}]")
                print(f"     • Summary   : {msg}")
                print("-" * 80)
            print("=" * 80 + "\n")
            return

        # Fallback to scans table if present
        cursor.execute(
            """
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'scans'
            );
            """
        )
        has_scans = cursor.fetchone()[0]

        if has_scans:
            cursor.execute(
                "SELECT scan_id, timestamp, total_tests, failed_tests, avg_risk_score, status FROM scans ORDER BY scan_id DESC LIMIT 1"
            )
            latest = cursor.fetchone()

            if latest:
                print("\n" + "=" * 80)
                print(" 🛡️  AI-SECOPS ASSESSMENT FRAMEWORK — LOG TERMINAL")
                print("=" * 80)
                print(f" LATEST RUN: #{latest[0]} | TIMESTAMP: {latest[1]}")
                print(f" AUDIT RESULT: {latest[5]}")
                print(f" STATUS: {latest[3]} Flaws Found out of {latest[2]} Injection Attempts")
                print(f" AVERAGE FRAMEWORK RISK INDEX: {latest[4]} / 10.0")
                print("=" * 80)

                cursor.execute(
                    "SELECT category, severity, payload, output, status, risk_score, recommendation FROM scan_results WHERE scan_id = %s",
                    (latest[0],),
                )
                results = cursor.fetchall()

                print("\n 🔍 DETAILED THREAT VECTOR BREAKDOWN:")
                print("-" * 80)
                for idx, row in enumerate(results, 1):
                    print(f" [{idx}] VULNERABILITY STATUS: [{row[4]}]")
                    print(f"     • Threat Class:    {row[0]} (Severity: {row[1]})")
                    print(f"     • Calculated Risk: {row[5]} / 10.0")
                    print(f'     • Attack Payload:  "{row[2]}"')
                    print(f'     • Target Output:   "{row[3]}"')
                    print(f"     • Fix Guidance:    {row[6]}")
                    print("-" * 80)
                return

        print("⚠️ Neither 'audit_events' nor 'scans' table found in database. Run database migrations first:")
        print("   python -m database.migrations.migrate")

    except Exception as e:
        print(f"❌ Error executing terminal data query: {e}")

    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()


if __name__ == "__main__":
    run()
