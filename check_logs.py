#!/usr/bin/env python3

import requests
import json

def check_logs():
    try:
        print("🔍 Checking dummy backend logs...")
        response = requests.get('http://localhost:9000/logs/recent?limit=10')
        
        if response.status_code == 200:
            data = response.json()
            logs = data['logs']
            
            print(f"📊 Total logs available: {data['total_count']}")
            print(f"📝 Showing last {len(logs)} logs:")
            print("=" * 80)
            
            normal_count = 0
            error_count = 0
            malicious_count = 0
            
            for i, log in enumerate(logs[-10:], 1):
                level = log['level']
                timestamp = log['timestamp']
                message = log['message'][:60]
                
                if level == 'ERROR':
                    error_count += 1
                    print(f"{i:2d}. 🔴 [{level}] {timestamp} - {message}...")
                elif any(keyword in message.lower() for keyword in ['script', 'alert', 'union', 'select', 'drop', 'http://']):
                    malicious_count += 1
                    print(f"{i:2d}. 🚨 [{level}] {timestamp} - {message}...")
                else:
                    normal_count += 1
                    print(f"{i:2d}. ✅ [{level}] {timestamp} - {message}...")
            
            print("=" * 80)
            print(f"📈 Log breakdown: Normal: {normal_count}, Error: {error_count}, Malicious: {malicious_count}")
            
        else:
            print(f"❌ Error: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to dummy backend at http://localhost:9000")
        print("Make sure dummy_backend.py is running")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    check_logs()