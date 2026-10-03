import json
import os
from pathlib import Path
import subprocess
import unittest


def walk(node):
    yield node
    for child in node.get("inner", []):
        yield from walk(child)


def calls(node):
    for child in walk(node):
        if child.get("kind") == "CallExpr":
            callee = child.get("inner", [])[:1]
            for ref in (item for part in callee for item in walk(part)):
                if ref.get("kind") == "DeclRefExpr":
                    yield ref.get("referencedDecl", {}).get("name")


class InlineMprSourceLifetimeTests(unittest.TestCase):
    def test_unknown_dispatch_preserves_the_live_stack_frame(self):
        source = Path(__file__).with_name("read_forward.c")
        result = subprocess.run([
            os.environ.get("CLANG", "clang"),
            "--target=x86_64-pc-windows-msvc", "-fms-extensions", "-ffreestanding",
            "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe", "-fno-ident",
            "-Wall", "-Wextra", "-Werror", "-O2", "-fsyntax-only",
            "-Xclang", "-ast-dump=json", str(source),
        ], capture_output=True, text=True, check=True)
        ast = json.loads(result.stdout)
        functions = {
            node["name"]: node for node in ast.get("inner", [])
            if node.get("kind") == "FunctionDecl"
            and any(child.get("kind") == "CompoundStmt" for child in node.get("inner", []))
        }
        function = functions["CheckInlineMpr"]
        body = next(child for child in function["inner"] if child.get("kind") == "CompoundStmt")
        statements = body["inner"]
        dispatch = next(i for i, node in enumerate(statements) if "IofCallDriver" in calls(node))
        resume = next(i for i, node in enumerate(statements) if "IofCompleteRequest" in calls(node))
        pre_resume = statements[dispatch + 1:resume]
        self.assertFalse(
            any(node.get("kind") == "ReturnStmt" for statement in pre_resume for node in walk(statement)),
            "unknown dispatch outcome must not return and discard retained IRP stack storage",
        )
        guards = [statement for statement in pre_resume if statement.get("kind") == "IfStmt"]
        self.assertTrue(guards, "uncertain dispatch outcome needs an explicit guard")
        parked = [functions[name] for guard in guards for name in calls(guard)
                  if name in functions and any(child.get("kind") == "C11NoReturnAttr"
                                              for child in functions[name].get("inner", []))]
        self.assertTrue(parked, "uncertain dispatch guard must enter a declared noreturn failure park")
        for park in parked:
            self.assertIn("DbgPrint", list(calls(park)))
            self.assertIn("KeDelayExecutionThread", list(calls(park)))
            self.assertTrue(any(node.get("kind") == "ForStmt" for node in walk(park)))
            self.assertTrue(any(node.get("kind") == "StringLiteral"
                                and "[read-forward-fail]" in node.get("value", "")
                                for node in walk(park)))
            self.assertFalse(set(calls(park)) & {"IoFreeIrp", "ExFreePoolWithTag", "IofCompleteRequest"})
            self.assertFalse(any(node.get("kind") == "ReturnStmt" for node in walk(park)))
        self.assertTrue(any(node.get("kind") == "ReturnStmt"
                            for statement in statements[resume + 1:] for node in walk(statement)),
                        "a witnessed real terminal result may return normally")


if __name__ == "__main__":
    unittest.main()
