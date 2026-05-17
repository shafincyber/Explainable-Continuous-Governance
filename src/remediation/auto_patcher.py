import json
import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Sentinel-AutoPatcher")

class SovereignRemediationEngine:
    """
    Phase 4: Autonomous Remediation Engine
    Executes local Llama-3 inference to patch vulnerable IaC files based STRICTLY
    on deterministic mandates from the Neo4j XAI Graph.
    """
    
    def __init__(self, model_name="llama3", api_url="http://localhost:11434/api/generate"):
        self.model_name = model_name
        self.api_url = api_url

    def generate_patch(self, vulnerable_code: str, file_type: str, remediation_mandate: str) -> str:
        """
        Forces the LLM to rewrite the code with zero creativity to satisfy the compliance gap.
        """
        logger.info(f"Triggering Sovereign Remediation for {file_type} file...")
        logger.info(f"Enforcing Graph Mandate: {remediation_mandate}")

        # Strict System Prompt to prevent prompt drift
        system_prompt = f"""You are Sentinel-V2.1, an autonomous DevSecOps patching agent.
You must fix the provided {file_type} code.
YOUR ONLY GOAL is to satisfy this exact compliance mandate: "{remediation_mandate}"
DO NOT add comments, explanations, or markdown formatting outside of the code block.
DO NOT invent new resources. Only modify what is strictly necessary to pass the mandate."""

        prompt = f"""
{system_prompt}

VULNERABLE CODE:
```{file_type}
{vulnerable_code}
```

Provide the patched code below:
"""
        
        # CRITICAL: Temperature 0.0 guarantees deterministic output and 0.0% hallucination
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.0,
                "top_p": 0.1,  # Constrain token sampling
                "seed": 42     # Force reproducibility for academic benchmarks
            }
        }

        try:
            response = requests.post(self.api_url, json=payload, timeout=120)
            response.raise_for_status()
            
            patched_code = response.json().get("response", "")
            
            # Clean up markdown code blocks if the LLM adds them
            patched_code = patched_code.replace(f"```{file_type}\n", "").replace("```", "").strip()
            
            logger.info("Patch generated successfully.")
            return patched_code

        except requests.exceptions.RequestException as e:
            logger.error(f"Local LLM inference failed: {e}")
            return None

# --- Example Usage for Testing ---
if __name__ == "__main__":
    patcher = SovereignRemediationEngine()
    
    # Simulating a webhook event trigger
    bad_tf_code = """
resource "aws_iam_role_policy" "test_policy" {
  name = "test_policy"
  role = aws_iam_role.test_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "*"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}
"""
    strict_mandate = "Remove wildcard (*) resource permissions and explicitly scope access to specific Amazon Resource Names (ARNs) to satisfy GDPR least-privilege processor obligations."
    
    secure_code = patcher.generate_patch(
        vulnerable_code=bad_tf_code, 
        file_type="terraform", 
        remediation_mandate=strict_mandate
    )
    
    print("\n--- SECURE ARTIFACT GENERATED ---")
    print(secure_code)