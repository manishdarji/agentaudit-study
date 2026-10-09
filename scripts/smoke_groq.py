"""One-task live check of the Groq setup. Costs a few thousand tokens of the free quota.

Windows PowerShell:   $env:GROQ_API_KEY="gsk_..."; python scripts/smoke_groq.py
macOS/Linux:          GROQ_API_KEY=gsk_... python scripts/smoke_groq.py
Optional:             GROQ_MODEL=openai/gpt-oss-20b  (default)   LOGGING_POINT=gateway|agent
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv

load_dotenv()


from agentaudit.agent.llm import DailyLimitReached, GroqClient, LLMError
from agentaudit.agent.loop import run_task
from agentaudit.agent.tasks import build_corpus, build_projects, check_task, generate_tasks, make_workspace
from agentaudit.agent.tools import Tools

work = os.path.join(os.path.dirname(__file__), "..", "runs", "smoke")
os.makedirs(work, exist_ok=True)
projects = build_projects()
make_workspace(os.path.join(work, "workspace"), projects)
tools = Tools(os.path.join(work, "workspace"), build_corpus(projects))
task = generate_tasks(1, projects)[0]
llm = GroqClient(cache_dir=os.path.join(work, "cache"), usage_path=os.path.join(work, "usage.json"))
events = []

print("model:", llm.model)
print("task :", task.text)
try:
    r = run_task(task, llm, tools, events.append, logging_point=os.environ.get("LOGGING_POINT", "gateway"))
except DailyLimitReached as e:
    sys.exit(f"Daily limit reached: {e}")
except LLMError as e:
    sys.exit(f"LLM error: {e}")

for e in events:
    print(f"  {e['kind']:9} {e['tool']:12} {e['args']}")
print("finished:", r.finished, "| final:", r.final)
print("LLM calls:", r.llm_calls, "| tokens:", r.prompt_tokens + r.completion_tokens, "| errors:", r.errors)
print("task actually succeeded:", check_task(task, tools))
