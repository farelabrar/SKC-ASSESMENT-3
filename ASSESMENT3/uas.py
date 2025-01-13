import re
from datetime import datetime
import pandas as pd
import logging
from collections import defaultdict
import numpy as np
from urllib.parse import unquote

class LogAnalyzer:
    def __init__(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='analysis.log'
        )
        
        # Attack patterns 6
        self.patterns = {
            'sql_injection': re.compile(r'(?i)(UNION|SELECT|INSERT|DELETE|UPDATE)'),
            'xss': re.compile(r'(?i)(<script>|javascript:)'),
            'path_traversal': re.compile(r'(?i)(\.\.\/|\.\./|%2e%2e%2f)'),
            'malicious_uri': re.compile(r'(?i)(slot|zeus|jackpot|jp|wd)'),  # 8
            'suspicious_encoding': re.compile(r'(%20|%2f|%2e){3,}')  # URL encoding check
        }

    def parse_line(self, line):
        """Parse single log line"""
        try:
            # Nginx log format standard
            pattern = r'(\d+\.\d+\.\d+\.\d+).*\[([^\]]+)\].*?"([^"]*)".*?(\d+)\s(\d+)'
            match = re.search(pattern, line)
            
            if match:
                ip, timestamp, request, status, bytes_sent = match.groups()
                # Parse timestamp
                timestamp = datetime.strptime(timestamp.split()[0], '%d/%b/%Y:%H:%M:%S')
                # Parse request parts
                method, path, _ = request.split(' ') if len(request.split()) >= 3 else (request, "/", "")
                
                return {
                    'ip': ip,
                    'timestamp': timestamp,
                    'method': method,
                    'path': path,
                    'status': status,
                    'bytes': bytes_sent
                }
            return None
        except Exception as e:
            logging.warning(f"Error parsing line: {str(e)}")
            return None

    def detect_attacks(self, entry):
        """Detect attacks based on patterns"""
        attacks = []
        path = entry['path']
        
        # Check each pattern
        for attack_type, pattern in self.patterns.items():
            if pattern.search(path):
                attacks.append(attack_type)
                
        # Additional checks 8
        # Check rapid requests (same IP, same URL, < 0.5s)
        if hasattr(self, 'last_request') and entry['ip'] == self.last_request['ip']:
            time_diff = (entry['timestamp'] - self.last_request['timestamp']).total_seconds()
            if time_diff < 0.5 and entry['path'] == self.last_request['path']:
                attacks.append('rapid_request')
                
        self.last_request = entry
        return attacks if attacks else ['normal']

    def detect_brute_force(self, df):
        """Detect brute force attempts (slide 6)"""
        # Group by IP and count failed attempts (401, 403)
        failed_attempts = df[df['status'].isin(['401', '403'])].groupby('ip').size()
        return failed_attempts[failed_attempts > 10]  # Threshold: 10 failed attempts

    def detect_dos(self, df):
        """Detect DoS attempts (slide 6)"""
        # Count requests per IP per minute
        df['minute'] = df['timestamp'].dt.floor('min')
        requests_per_minute = df.groupby(['ip', 'minute']).size()
        return requests_per_minute[requests_per_minute > 100]  # Threshold: 100 requests/minute

    def process_logs(self, input_file, limit=1000000):
        """Process log file"""
        logging.info(f"Mulai memproses {input_file}")
        data = []
        line_count = 0
        
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line_count >= limit:
                        break
                        
                    entry = self.parse_line(line)
                    if entry:
                        entry['attack_types'] = self.detect_attacks(entry)
                        data.append(entry)
                    
                    line_count += 1
                    if line_count % 100000 == 0:
                        logging.info(f"Processed {line_count} lines")
        
        except Exception as e:
            logging.error(f"Error reading file: {str(e)}")
            return None
            
        return data

    def analyze(self, old_log, new_log, output_file, limit=1000000):
        """Main analysis function"""
        try:
            # Process both logs
            old_data = self.process_logs(old_log, limit)
            new_data = self.process_logs(new_log, limit)
            
            if not old_data or not new_data:
                logging.error("Error processing log files")
                return
                
            # Convert to DataFrame
            old_df = pd.DataFrame(old_data)
            new_df = pd.DataFrame(new_data)
            
            # Combine data
            df = pd.concat([old_df, new_df])
            
            # Save detailed results
            df.to_csv(output_file, index=False)
            
            # Detect additional attack patterns
            brute_force = self.detect_brute_force(df)
            dos_attempts = self.detect_dos(df)
            
            # Create summary
            self.create_summary(df, brute_force, dos_attempts, 
                              output_file.replace('.csv', '_summary.txt'))
            
            logging.info("Analysis complete")
            
        except Exception as e:
            logging.error(f"Error in analysis: {str(e)}")
            raise

    def create_summary(self, df, brute_force, dos_attempts, output_file):
        """Create analysis summary"""
        with open(output_file, 'w') as f:
            f.write("Log Analysis Summary\n")
            f.write("===================\n\n")
            
            # Attack Distribution
            f.write("1. Attack Distribution:\n")
            attack_counts = df.explode('attack_types')['attack_types'].value_counts()
            for attack, count in attack_counts.items():
                f.write(f"{attack}: {count}\n")
            
            # IP Analysis
            f.write("\n2. Top 5 Source IPs:\n")
            ip_counts = df['ip'].value_counts().head()
            for ip, count in ip_counts.items():
                f.write(f"{ip}: {count}\n")
            
            # Status Code Distribution
            f.write("\n3. Status Code Distribution:\n")
            status_counts = df['status'].value_counts()
            for status, count in status_counts.items():
                f.write(f"{status}: {count}\n")
            
            # Brute Force Analysis
            f.write("\n4. Brute Force Attempts:\n")
            f.write(f"Total IPs detected: {len(brute_force)}\n")
            if not brute_force.empty:
                f.write("Top offending IPs:\n")
                for ip, attempts in brute_force.head().items():
                    f.write(f"{ip}: {attempts} failed attempts\n")
            
            # DoS Analysis
            f.write("\n5. DoS Attempts:\n")
            f.write(f"Total suspicious intervals: {len(dos_attempts)}\n")
            if not dos_attempts.empty:
                f.write("Sample of high-traffic intervals:\n")
                for (ip, minute), requests in dos_attempts.head().items():
                    f.write(f"{ip} at {minute}: {requests} requests/minute\n")

def main():
    base_dir = "D:\TUGAS SEMESTER 5\SKC\ASSESMENT3"
    old_log = f"{base_dir}\\old.log"
    new_log = f"{base_dir}\\new.log"
    output_file = f"{base_dir}\\analysis_results.csv"
    
    analyzer = LogAnalyzer()
    analyzer.analyze(old_log, new_log, output_file, limit=1000000)

if __name__ == "__main__":
    main()