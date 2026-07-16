import os
import sqlite3
import psycopg2
from datetime import datetime

class SecurityDatabase:
    def __init__(self):
        self.init_db()

    def get_connection(self):
        """Creates and returns a new connection instance to PostgreSQL."""
        return psycopg2.connect(
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            dbname=os.getenv("DB_NAME")
        )

    def init_db(self):
        """Initializes tables using PostgreSQL syntax."""
        conn = self.get_connection()
       
        cursor = conn.cursor()
            
        cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id SERIAL PRIMARY KEY ,
                    timestamp TEXT NOT NULL,
                    total_tests INTEGER NOT NULL,
                    failed_tests INTEGER NOT NULL,
                    avg_risk_score REAL NOT NULL,
                    status TEXT NOT NULL
                )
        ''')
            
        cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    result_id SERIAL PRIMARY KEY ,
                    scan_id INTEGER NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    output TEXT NOT NULL,
                    status TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    recommendation TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
                )
            ''')
        conn.commit()

    def save_scan_report(self, summary: dict, details: list) -> int:
        """Saves everything from the active test loop into PostgreSQL."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # 1. Use RETURNING scan_id to fetch the real ID immediately from Postgres
            cursor.execute('''
                INSERT INTO scans (timestamp, total_tests, failed_tests, avg_risk_score, status)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING scan_id;
            ''', (
                datetime.now(),
                summary["total_tests"],
                summary["failed_tests"],
                summary["avg_risk_score"],
                summary["status"]
            ))
            
            scan_id = cursor.fetchone()[0]
            
            # 2. Loop through child records using %s formatting strings
            for item in details:
                cursor.execute('''
                    INSERT INTO scan_results (scan_id, category, severity, payload, output, status, risk_score, recommendation)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ''', (
                    scan_id,
                    item["category"],
                    item["severity"],
                    item["payload"],
                    item["output"],
                    item["status"],
                    item["risk_score"],
                    item["recommendation"]
                ))
            
            conn.commit()
            return scan_id

        except Exception as e:
            conn.rollback()
            print(f"Database error while saving scan report: {e}")
            raise e
        finally:
            cursor.close()
            conn.close()
        
    def generate_markdown_report(self, scan_id: int):
        """Generates a professional Markdown audit report document."""
        report_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
        os.makedirs(report_dir, exist_ok=True)
        report_file = os.path.join(report_dir, f"security_report_#{scan_id}.md")
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Swapped '?' with '%s' for safe PostgreSQL parameter parsing
            cursor.execute(
                "SELECT timestamp, total_tests, failed_tests, avg_risk_score, status FROM scans WHERE scan_id = %s", 
                (scan_id,)
            )
            scan = cursor.fetchone()
            
            cursor.execute(
                "SELECT category, severity, payload, output, status, risk_score, recommendation FROM scan_results WHERE scan_id = %s", 
                (scan_id,)
            )
            results = cursor.fetchall()
            
            if not scan:
                print(f"Error: No report metrics found for Scan ID #{scan_id}")
                return

            markdown_content = f"""# 🛡️ AI-SecOps Security Audit Compliance Report
**Generated Timestamp:** {scan[0]}  
**Scan Run ID:** #{scan_id}  
**Overall Audit Status:** `{scan[4]}`

## 📊 Executive Summary
* **Total Threat Vectors Simulated:** {scan[1]}
* **Successful Exploits Detected:** {scan[2]}
* **Calculated Framework Risk Index:** {scan[3]} / 10.0

---

## 🔍 Detailed Threat Vector Breakdown
"""
            for idx, row in enumerate(results, 1):
                markdown_content += f"""
### [{idx}] {row[0]}
* **Severity Class:** {row[1]}
* **Scanner Finding Metric:** `{row[4]}` (Risk Score: {row[5]}/10.0)
* **Injected Attack Vector:** `{row[2]}`
* **Target System Response:** *\"{row[3]}\"*
* **💡 Remediations & Engineering Mitigations:** {row[6]}

---
"""
            with open(report_file, "w") as f:
                f.write(markdown_content)
            print(f"📝 Compliance Report Document generated at: /reports/security_report_#{scan_id}.md")

        except Exception as e:
            print(f"❌ Error compiling Markdown report doc: {e}")
        finally:
            cursor.close()
            conn.close()