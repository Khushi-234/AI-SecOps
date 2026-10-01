"""
AI-SecOps Framework v1 — Dashboard Runner.

Supports running both:
- Streamlit Web Dashboard: streamlit run dashboard.py (or streamlit run dashboard/app.py)
- Terminal Audit Logger: python dashboard.py
"""

import os
import sys
from dotenv import load_dotenv

load_dotenv()

# Detect if executing inside Streamlit runtime context
def _is_streamlit_runtime() -> bool:
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        return get_script_run_ctx() is not None
    except Exception:
        return False


if _is_streamlit_runtime():
    from dashboard.app import main
    main()
else:
    import psycopg2

    def run():
        try:
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
            cursor.execute(
                """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'audit_events'
                );
                """
            )
            row = cursor.fetchone()
            has_audit_events = row[0] if row else False

            if has_audit_events:
                cursor.execute("SELECT COUNT(*) FROM audit_events;")
                cnt_row = cursor.fetchone()
                total_count = cnt_row[0] if cnt_row else 0

                cursor.execute(
                    "SELECT event_id, request_id, timestamp, component, event_type, severity, action, status, message "
                    "FROM audit_events ORDER BY timestamp DESC LIMIT 10"
                )
                rows = cursor.fetchall()

                print("\n" + "=" * 80)
                print(" 🛡️  AISECOPS — AUDIT LOG TERMINAL")
                print("=" * 80)
                print(f" TOTAL PERSISTED AUDIT EVENTS : {total_count}")
                print(f" DISPLAYING RECENT EVENTS     : {len(rows)}")
                print("=" * 80)

                if not rows:
                    print("\n⚠️ No audit records found in 'audit_events' table.")
                else:
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
                    print("=" * 80)

                print("\n💡 Tip: Launch the interactive Streamlit Web Dashboard UI with:")
                print("   .venv/bin/streamlit run dashboard.py\n")
                return

            print("⚠️ Table 'audit_events' not found in database. Run database migrations first:")
            print("   .venv/bin/python -m database.migrations.migrate")

        except Exception as e:
            print(f"❌ Error executing terminal data query: {e}")

        finally:
            if 'cursor' in locals() and cursor:
                cursor.close()
            if 'conn' in locals() and conn:
                conn.close()

    if __name__ == "__main__":
        run()
