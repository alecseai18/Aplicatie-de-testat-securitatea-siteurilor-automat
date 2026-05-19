"""CTF Aggressive Scanner package."""

__all__ = ["Scanner", "Finding", "Form"]


def __getattr__(name):
    if name in __all__:
        from .models import Finding, Form
        from .scanner import Scanner

        return {'Scanner': Scanner, 'Finding': Finding, 'Form': Form}[name]
    raise AttributeError(name)
