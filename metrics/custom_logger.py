"""
Custom LiteLLM Logger for Token/Cost Metrics
=============================================
Logs every API call's usage data to a JSONL file for analysis.
"""
import json
import os
from datetime import datetime
from pathlib import Path
from litellm.integrations.custom_logger import CustomLogger


class MetricsFileLogger(CustomLogger):
    """Logs LiteLLM usage metrics to a JSONL file."""

    def __init__(self):
        self.log_dir = Path(os.environ.get("METRICS_LOG_DIR", "/app/logs"))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "usage.jsonl"

    def _write_log(self, entry: dict):
        """Append a log entry to the JSONL file."""
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[MetricsFileLogger] Error writing log: {e}")

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        """Synchronous success callback."""
        self._log_event(kwargs, response_obj, start_time, end_time, success=True)

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        """Async success callback - called for streaming responses."""
        self._log_event(kwargs, response_obj, start_time, end_time, success=True)

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        """Synchronous failure callback."""
        self._log_event(kwargs, response_obj, start_time, end_time, success=False)

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        """Async failure callback."""
        self._log_event(kwargs, response_obj, start_time, end_time, success=False)

    def _log_event(self, kwargs, response_obj, start_time, end_time, success: bool):
        """Extract and log usage metrics."""
        try:
            # Extract model info
            model = kwargs.get("model", "unknown")
            litellm_params = kwargs.get("litellm_params", {})
            custom_llm_provider = litellm_params.get("custom_llm_provider", "")

            # Calculate latency
            latency_ms = 0
            if start_time and end_time:
                latency_ms = (end_time - start_time).total_seconds() * 1000

            # Extract usage from response
            usage = {}
            if response_obj:
                if hasattr(response_obj, "usage") and response_obj.usage:
                    usage_obj = response_obj.usage
                    if hasattr(usage_obj, "model_dump"):
                        usage = usage_obj.model_dump()
                    elif hasattr(usage_obj, "dict"):
                        usage = usage_obj.dict()
                    elif isinstance(usage_obj, dict):
                        usage = usage_obj
                    else:
                        # Manual extraction
                        usage = {
                            "prompt_tokens": getattr(usage_obj, "prompt_tokens", 0),
                            "completion_tokens": getattr(usage_obj, "completion_tokens", 0),
                            "total_tokens": getattr(usage_obj, "total_tokens", 0),
                        }
                elif isinstance(response_obj, dict) and "usage" in response_obj:
                    usage = response_obj["usage"]

            # Extract standard logging payload if available
            standard_payload = kwargs.get("standard_logging_object", {})
            response_cost = standard_payload.get("response_cost", 0) if standard_payload else 0

            # Build log entry
            entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "model": model,
                "provider": custom_llm_provider,
                "success": success,
                "latency_ms": round(latency_ms, 2),
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
                "cache_read_tokens": usage.get("cache_read_input_tokens", 0),
                "cache_creation_tokens": usage.get("cache_creation_input_tokens", 0),
                "cost_usd": response_cost,
            }

            self._write_log(entry)

        except Exception as e:
            print(f"[MetricsFileLogger] Error logging event: {e}")
            import traceback
            traceback.print_exc()


# Instance for LiteLLM to use
metrics_logger = MetricsFileLogger()
