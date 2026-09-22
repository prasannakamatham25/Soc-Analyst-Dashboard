import pandas as pd
import re

def parse_log_file(uploaded_file):
    try:
        filename = uploaded_file.name
        
        # 1. CSV File Handling
        if filename.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
            
            # Map IP Column
            ip_cols = [c for c in df.columns if 'ip' in c.lower() or 'source' in c.lower()]
            if ip_cols:
                df['Source_IP'] = df[ip_cols[0]]
            elif 'Source_IP' not in df.columns:
                df['Source_IP'] = '192.168.1.100'

            # Map Severity Column
            sev_cols = [c for c in df.columns if 'sev' in c.lower() or 'level' in c.lower() or 'priority' in c.lower()]
            if sev_cols:
                df['Severity'] = df[sev_cols[0]].astype(str).str.upper()
            elif 'Severity' not in df.columns:
                df['Severity'] = 'HIGH'

            return df

        # 2. LOG / TXT File Handling
        else:
            uploaded_file.seek(0)
            lines = uploaded_file.getvalue().decode("utf-8", errors="ignore").splitlines()
            parsed_logs = []
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            
            for idx, line in enumerate(lines):
                ip_match = re.search(ip_pattern, line)
                ip = ip_match.group(0) if ip_match else f"10.0.0.{(idx % 10) + 1}"
                
                line_lower = line.lower()
                if "failed" in line_lower or "error" in line_lower or "critical" in line_lower:
                    severity = "CRITICAL"
                elif "warning" in line_lower or "denied" in line_lower:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
                    
                parsed_logs.append({
                    "Log_ID": idx + 1,
                    "Raw_Log": line,
                    "Source_IP": ip,
                    "Severity": severity
                })
                
            return pd.DataFrame(parsed_logs)

    except Exception as e:
        return pd.DataFrame({
            "Log_ID": [1],
            "Source_IP": ["127.0.0.1"],
            "Severity": ["CRITICAL"],
            "Message": [f"Parsing Error: {str(e)}"]
        })
        