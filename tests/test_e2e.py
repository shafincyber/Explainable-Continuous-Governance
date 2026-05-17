import requests, time, os, sys

def test_e2e_pipeline():
    print("[*] Initiating E2E Pipeline Simulation...")
    api_url = "http://localhost:8000/api/v2/scan"
    dataset_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dataset")
    target_file = os.path.join(dataset_dir, "main_patched.tf")

    if os.path.exists(target_file):
        os.remove(target_file)

    payload = {"repository_url": "sentinel-e2e-test", "commit_hash": "simulation", "branch": "main"}
    
    try:
        r = requests.post(api_url, json=payload, timeout=5)
        assert r.status_code == 200, f"API failed: {r.status_code}"
        print("[+] Webhook accepted. Kafka event published.")
    except Exception as e:
        assert False, f"API Offline: {e}"
        
    print("[*] Awaiting Sovereign AI autonomous remediation (Timeout: 180s)...")
    patched = False
    for i in range(180):
        if os.path.exists(target_file):
            patched = True
            break
        time.sleep(1)
    
    assert patched, "E2E Failure: Autonomous patcher did not execute in time."
    print("[+] SUCCESS: End-to-End Event-Driven Pipeline Verified!")
    os.remove(target_file)
    print("[*] Cleaned up E2E artifacts.")

if __name__ == "__main__":
    test_e2e_pipeline()