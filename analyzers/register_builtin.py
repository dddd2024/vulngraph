"""
Built-in analyzer registration entry point.

Calls each language sub-module's ``register_analyzers()`` to populate
the given ``AnalyzerRegistry`` with all built-in analyzers.

To add a new built-in analyzer, only the corresponding language
``register.py`` needs to be modified — no changes to
``audit_core/registry.py`` are required.
"""

from __future__ import annotations

from audit_core.registry import AnalyzerRegistry


def register_builtin_analyzers(registry: AnalyzerRegistry) -> None:
    """
    Register all built-in analyzers into the given registry.

    Delegates to each language sub-module's ``register_analyzers()``:
    - analyzers/python/register.py
    - analyzers/javascript/register.py
    - analyzers/java/register.py
    - analyzers/c_cpp/register.py
    - analyzers/taint/register.py

    Args:
        registry: The AnalyzerRegistry instance to populate.
    """
    from analyzers.python.register import register_analyzers as register_python
    from analyzers.javascript.register import register_analyzers as register_javascript
    from analyzers.java.register import register_analyzers as register_java
    from analyzers.c_cpp.register import register_analyzers as register_c_cpp
    from analyzers.taint.register import register_analyzers as register_taint

    register_python(registry)
    register_javascript(registry)
    register_java(registry)
    register_c_cpp(registry)
    register_taint(registry)
