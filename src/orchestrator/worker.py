from kafka import KafkaConsumer
import subprocess
import requests
import json
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(BASE_DIR)

from src.graph_db.neo4j_client import ComplianceGraph
from src.semantic_engine.llama_guard import sanitize_manifest
from src.remediation.auto_patcher import SovereignRemediationEngine

OLLAMA_URL = "http://localhost:11434/api/generate"

def emit_alert(trigger_id, regulations, status):
    try:
        requests.post("http://localhost:8000/api/v2/alert", json={
            "trigger_id": trigger_id, "regulations": regulations, "status": status
        }, timeout=1.5)
    except Exception: pass

def emit_log(source, message):
    try:
        requests.post("http://localhost:8000/api/v2/log_sink", json={"source": source, "message": str(message)}, timeout=1.5)
    except Exception: pass

def get_checkov_path():
    import shutil
    # 1. Primary: Check standard system PATH resolution
    p = shutil.which('checkov')
    if p: return p
    
    # 2. Secondary: Explicitly target the active Virtual Environment Scripts folder
    venv_scripts = os.path.join(sys.prefix, 'Scripts')
    for ext in ['.exe', '.cmd', '.bat', '']:
        target = os.path.join(venv_scripts, f'checkov{ext}')
        if os.path.exists(target):
            return target
            
    return None

def run_checkov_scan(target_dir):
    emit_log('audit', f"[*] Executing Deterministic Scanner (Checkov) on {target_dir}...")
    print(f"[*] Executing Deterministic Scanner (Checkov) on {target_dir}...")
    try:
        checkov_exe = get_checkov_path()
        
        if not checkov_exe:
            error_msg = f"[-] FATAL: Checkov executable is completely missing from the virtual environment ({sys.prefix}). Run: pip install checkov -I --no-cache-dir"
            print(error_msg)
            emit_log('audit', error_msg)
            return []

        # Execute the absolute binary path
        cmd = f'"{checkov_exe}" -d "{target_dir}" -o json --quiet'
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        
        if not result.stdout.strip():
            error_msg = f"[-] Checkov execution failed. Stderr: {result.stderr.strip()}"
            print(error_msg)
            emit_log('audit', error_msg)
            return []
        
        # Slices output to guarantee clean JSON parsing
        output = result.stdout.strip()
        json_start = output.find('{')
        list_start = output.find('[')
        
        if json_start == -1 and list_start == -1:
            error_msg = f"[-] Checkov did not output valid JSON: {output[:200]}"
            print(error_msg)
            emit_log('audit', error_msg)
            return []
            
        start_idx = min(i for i in [json_start, list_start] if i > -1)
        clean_json = output[start_idx:]

        report = json.loads(clean_json)
        findings = []
        reports = report if isinstance(report, list) else [report]
        
        for r in reports:
            if "results" in r and "failed_checks" in r["results"]:
                for check in r["results"]["failed_checks"]:
                    file_path = os.path.join(target_dir, check.get("file_path", "").lstrip("\\/"))
                    findings.append({"id": check["check_id"], "file": file_path})
                    
        unique_findings = [dict(t) for t in {tuple(d.items()) for d in findings}]
        return unique_findings
    except Exception as e:
        print(f"[-] Checkov Runtime Error: {e}")
        emit_log('audit', f"[-] Checkov Runtime Error: {e}")
        return []

def run_semantic_scan(manifest_path):
    emit_log('audit', f"[*] Initializing Sovereign Semantic Layer for {manifest_path}...")
    print(f"[*] Initializing Sovereign Semantic Layer for {manifest_path}...")
    try:
        with open(manifest_path, 'r', encoding='utf-8-sig') as f:
            content = f.read()
            if not content.strip(): return []
            raw_manifest = json.loads(content)
            
        safe_manifest = sanitize_manifest(raw_manifest)
        
        prompt = f"""
        Act as an expert European IT Auditor enforcing the EU AI Act.
        Review the following software manifest. Identify if there are any unverified Generative AI dependencies or telemetry libraries that could violate data governance or supply chain security.
        Manifest: {json.dumps(safe_manifest)}
        You MUST respond ONLY with a valid JSON object containing a "violation" boolean and a "technical_trigger" string. 
        If a risk is detected, the technical_trigger MUST be exactly: "unauthenticated_third_party_api". Do not invent new trigger names.
        Example Output: {{"violation": true, "technical_trigger": "unauthenticated_third_party_api"}}
        """
        
        response = requests.post(OLLAMA_URL, json={"model": "llama3", "prompt": prompt, "stream": False, "options": {"num_ctx": 2048, "num_thread": 4, "temperature": 0.0}})
        if response.status_code != 200: return []

        llm_output = response.json().get("response", "{}")
        start_idx = llm_output.find('{')
        end_idx = llm_output.rfind('}')
        
        if start_idx != -1 and end_idx != -1:
            result = json.loads(llm_output[start_idx:end_idx + 1])
            if result.get("violation"):
                trigger_val = result.get('technical_trigger')
                emit_log('audit', f"[!] Semantic Risk Detected: {trigger_val}")
                print(f"[!] Semantic Risk Detected: {trigger_val}")
                return [trigger_val]
        return []
    except Exception as e:
        print(f"[-] Semantic Engine Error: {e}")
        return []

def run_worker():
    print("[*] Starting Sentinel-V2 Kafka Worker...")
    graph = ComplianceGraph()
    
    try:
        consumer = KafkaConsumer('sentinel-scans', bootstrap_servers=['localhost:9092'], auto_offset_reset='earliest', enable_auto_commit=True, group_id='sentinel-worker-group', value_deserializer=lambda m: json.loads(m.decode('utf-8')))
        emit_log('audit', '[+] Worker is actively listening to kafka topic...')
        print("[+] Worker is actively listening to 'sentinel-scans' topic...\n")
    except Exception as e:
        print(f"[-] Ensure Docker containers are running. Error: {e}")
        return

    for message in consumer:
        job = message.value
        print(f"\n==================================================")
        emit_log('audit', f"\n==================================================\n[*] NEW JOB RECEIVED: Scanning {job['repository_url']}")
        print(f"[*] NEW JOB RECEIVED: Scanning {job['repository_url']} (Commit: {job['commit_hash']})")
        
        target_directory = os.path.join(BASE_DIR, "dataset")
        manifest_file = os.path.join(target_directory, "package.json")
        
        all_triggers = []
        remediation_map = {}
        
        checkov_findings = run_checkov_scan(target_directory)
        if checkov_findings:
            extracted_ids = [f["id"] for f in checkov_findings]
            emit_log('audit', f"[!] Deterministic Engine flagged: {extracted_ids}")
            print(f"[!] Deterministic Engine flagged: {extracted_ids}")
            all_triggers.extend(extracted_ids)
            
        if os.path.exists(manifest_file):
            semantic_findings = run_semantic_scan(manifest_file)
            all_triggers.extend(semantic_findings)
        
        if all_triggers:
            emit_log('audit', '[*] Querying Neo4j XAI Compliance Graph...')
            print("\n[*] Querying Neo4j XAI Compliance Graph...")
            audit_report = []
            for trigger in list(set(all_triggers)):
                legal_context = graph.get_legal_context(trigger)
                if legal_context:
                    audit_report.extend(legal_context)
                    remediation_map[trigger] = legal_context
            
            if audit_report:
                formatted_audit = json.dumps(audit_report, indent=2)
                emit_log('audit', f"[+] Explainable Audit Generation Complete:\n{formatted_audit}")
                print("[+] Explainable Audit Generation Complete:")
                print(formatted_audit)
            else:
                emit_log('audit', '[*] Technical vulnerabilities detected; initializing baseline mappings.')
        else:
            emit_log('audit', '[+] Pipeline secure. No compliance violations detected.')
            print("[+] Pipeline secure. No compliance violations detected.")

        if checkov_findings:
            emit_log('remediation', '[*] Initiating Autonomous Remediation Engine...\n[*] --------------------------------------------------')
            print("\n[*] --------------------------------------------------")
            print("[*] PHASE 4: Initiating Autonomous Remediation Engine...")
            
            patcher = SovereignRemediationEngine()
            
            for finding in checkov_findings:
                trigger_id = finding["id"]
                target_file = finding["file"]
                legal_data = remediation_map.get(trigger_id)
                
                if os.path.exists(target_file):
                    # FALLBACK POLICY ENGINE
                    if legal_data and len(legal_data) > 0:
                        reg_list = ", ".join(list(set([ctx.get("Regulation", "") for ctx in legal_data])))
                        remediation_mandate = legal_data[0].get("standard_remediation", "")
                    else:
                        reg_list = "Baseline Cyber-Hygiene (NIS2 Art 21 Policy)"
                        remediation_mandate = f"Remediate infrastructure misconfiguration rule {trigger_id} by implementing strict secure defaults following industry-standard benchmark parameters."
                    
                    emit_alert(trigger_id, reg_list, "VIOLATION_DETECTED")
                    emit_log('remediation', f"[*] Llama-3 rewriting {os.path.basename(target_file)} to enforce {reg_list}...")
                    print(f"[*] Llama-3 rewriting {os.path.basename(target_file)} to enforce {reg_list}...")
                    
                    with open(target_file, 'r', encoding='utf-8') as tf_f:
                        vulnerable_code = tf_f.read()
                    
                    file_type = "terraform" if target_file.endswith(".tf") else "yaml"
                    
                    patched_code = patcher.generate_patch(vulnerable_code, file_type, remediation_mandate)
                    
                    if patched_code and patched_code.strip():
                        patched_filename = target_file.replace('.tf', '_patched.tf').replace('.yaml', '_patched.yaml')
                        with open(patched_filename, 'w', encoding='utf-8') as tf_f:
                            tf_f.write(patched_code)
                        
                        emit_log('remediation', f"[+] SUCCESS: {trigger_id} remediated. Code saved to {os.path.basename(patched_filename)}\n")
                        print(f"[+] SUCCESS: {trigger_id} remediated. Code saved to {os.path.basename(patched_filename)}")
                        emit_alert(trigger_id, reg_list, "REMEDIATED")
                    else:
                        emit_log('remediation', f"[-] FAILURE: Could not generate patch for {trigger_id}\n")
                        print(f"[-] FAILURE: Could not generate patch for {trigger_id}")
                    
            emit_log('remediation', '[*] --------------------------------------------------')
            print("[*] --------------------------------------------------")
        print(f"==================================================\n")

if __name__ == "__main__":
    try:
        run_worker()
    except KeyboardInterrupt:
        print("\n[*] Shutting down worker...")
        sys.exit(0)