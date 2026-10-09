"""The agent's tools: document search, sandboxed files, calculator, mock email.

execute() never raises: any failure becomes an 'ERROR: ...' string the model can read and react to,
which is also what a real tool gateway would return.
"""
import ast
import json
import operator
import os
import re

MAX_FILE_CHARS = 20_000


class SandboxError(Exception):
    pass


class Sandbox:
    """Confines file access to one directory (no absolute paths, no '..', no symlink escapes)."""

    def __init__(self, root: str):
        os.makedirs(root, exist_ok=True)
        self.root = os.path.realpath(root)

    def resolve(self, rel) -> str:
        if not isinstance(rel, str) or not rel.strip():
            raise SandboxError("path must be a non-empty string")
        if os.path.isabs(rel) or rel[0] in "/\\" or (len(rel) > 1 and rel[1] == ":"):
            raise SandboxError("absolute paths are not allowed")
        full = os.path.realpath(os.path.join(self.root, rel))
        try:
            inside = os.path.commonpath([os.path.normcase(self.root), os.path.normcase(full)]) == os.path.normcase(self.root)
        except ValueError:  # different drives on Windows
            inside = False
        if not inside:
            raise SandboxError("path escapes the sandbox")
        return full


# ----------------------------------------------------------------------------- calculator
_BIN = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod, ast.Pow: operator.pow,
}
_UN = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def safe_eval(expr: str):
    """Arithmetic only. Anything else (names, calls, attributes) is rejected."""
    if not isinstance(expr, str) or len(expr) > 200:
        raise ValueError("expression must be a string of at most 200 characters")

    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _BIN:
            a, b = ev(node.left), ev(node.right)
            if isinstance(node.op, ast.Pow) and (abs(b) > 100 or abs(a) > 1e6):
                raise ValueError("exponent too large")
            return _BIN[type(node.op)](a, b)
        if isinstance(node, ast.UnaryOp) and type(node.op) in _UN:
            return _UN[type(node.op)](ev(node.operand))
        raise ValueError("only numbers and + - * / // % ** ( ) are allowed")

    return ev(ast.parse(expr.strip(), mode="eval"))


def _fmt_number(x) -> str:
    if isinstance(x, float) and x.is_integer():
        return str(int(x))
    return format(x, ".10g") if isinstance(x, float) else str(x)


# ----------------------------------------------------------------------------- tools
def _fn(name, desc, props, required):
    return {"type": "function", "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object", "properties": props, "required": required}}}


_S = {"type": "string"}
SCHEMAS = [
    _fn("search_docs", "Search the company documents. Returns the best matching documents.", {"query": _S}, ["query"]),
    _fn("read_file", "Read a text file in the workspace.", {"path": _S}, ["path"]),
    _fn("write_file", "Write a text file in the workspace (overwrites).", {"path": _S, "content": _S}, ["path", "content"]),
    _fn("list_files", "List files in a workspace folder.", {"path": _S}, []),
    _fn("delete_file", "Delete a file in the workspace.", {"path": _S}, ["path"]),
    _fn("calculator", "Evaluate an arithmetic expression such as 0.15 * 120000.", {"expression": _S}, ["expression"]),
    _fn("send_email", "Send an email.", {"to": _S, "subject": _S, "body": _S}, ["to", "subject", "body"]),
]


class Tools:
    def __init__(self, sandbox_root: str, corpus: dict, max_result_chars: int = 1500):
        self.sandbox = Sandbox(sandbox_root)
        self.corpus = corpus
        self.outbox = []
        self.max_result_chars = max_result_chars

    def schemas(self) -> list:
        return [dict(s) for s in SCHEMAS]

    def execute(self, name: str, args) -> str:
        try:
            if not isinstance(args, dict):
                raise ValueError("arguments must be a JSON object")
            fn = getattr(self, "_t_" + name, None)
            if fn is None or name.startswith("_"):
                return f"ERROR: unknown tool '{name}'"
            out = str(fn(**args))
        except TypeError as e:
            return f"ERROR: bad arguments for {name}: {e}"
        except SandboxError as e:
            return f"ERROR: {e}"
        except (OSError, ValueError, SyntaxError, ZeroDivisionError, OverflowError) as e:
            return f"ERROR: {e}"
        if len(out) > self.max_result_chars:
            out = out[: self.max_result_chars] + "...[truncated]"
        return out

    # -- individual tools
    def _t_search_docs(self, query):
        words = {w for w in re.findall(r"[a-z0-9@.\-]{3,}", str(query).lower())}
        scored = []
        for title, text in self.corpus.items():
            hay = (title + " " + text).lower()
            score = sum(1 for w in words if w in hay)
            if score:
                scored.append((-score, title, text))
        if not scored:
            return "No matching documents."
        scored.sort()
        return "\n".join(f"[{t}] {x}" for _, t, x in scored[:2])

    def _t_read_file(self, path):
        with open(self.sandbox.resolve(path), "r", encoding="utf-8", errors="replace") as f:
            return f.read(MAX_FILE_CHARS)

    def _t_write_file(self, path, content):
        content = str(content)
        if len(content) > MAX_FILE_CHARS:
            raise ValueError("content too long")
        full = self.sandbox.resolve(path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)
        return f"wrote {len(content)} characters to {path}"

    def _t_list_files(self, path="."):
        full = self.sandbox.resolve(path or ".")
        return "\n".join(sorted(os.listdir(full))) or "(empty)"

    def _t_delete_file(self, path):
        full = self.sandbox.resolve(path)
        if os.path.isdir(full):
            raise ValueError("path is a directory")
        os.remove(full)
        return f"deleted {path}"

    def _t_calculator(self, expression):
        return _fmt_number(safe_eval(expression))

    def _t_send_email(self, to, subject, body):
        if "@" not in str(to):
            raise ValueError("invalid recipient address")
        self.outbox.append({"to": str(to), "subject": str(subject), "body": str(body)})
        return f"email sent to {to}"
