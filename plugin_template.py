"""Example r3dProxy scanner plugin.

Copy this file into  ~/.r3dproxy/plugins/  and edit it. r3dProxy loads every
*.py there on startup (or when you hit ⟳ reload in the Scanner tab) and expects
either a module-level `plugin = ...` or a `PLUGINS = [...]` list.

Injection point: the user wraps the value to test in §…§ in the request. Use
sub_marker(base_text, payload) to build each test request.
"""
from r3dproxy.core.plugins.base import (Plugin, Case, sub_marker, point_label,
                                         FIRM, HIGH, TENTATIVE, INFO)


class ExampleHeaderReflection(Plugin):
    id = "example-reflect"
    name = "Example: header reflection"
    owasp = "A03:2021 Injection"
    description = "Demo plugin — flags when a unique token is reflected verbatim."

    def build_cases(self, base_text, marker):
        token = "r3dtmpl123"
        return [Case(label="reflect probe",
                     request_text=sub_marker(base_text, token),
                     payload=token,
                     meta={"token": token})]

    def detect(self, case, resp, engine):
        token = case.meta["token"]
        if resp.ok and token in resp.body:
            return self._finding(case, resp, INFO,
                                 f"Token {token} reflected in response body.",
                                 point_label(engine.base_text))
        return None


plugin = ExampleHeaderReflection()
