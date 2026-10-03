"""Strip NUL (\\x00) from everything written to the database.

PostgreSQL rejects NUL in text and JSON, so one hostile banner, page title or header from a
scanned host could otherwise crash persistence for a whole scan. Scanned hosts are untrusted.
"""
from sqlalchemy import event, inspect
from sqlalchemy.orm import Session


def clean(value):
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, dict):
        return {clean(k): clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v) for v in value]
    if isinstance(value, tuple):
        return tuple(clean(v) for v in value)
    return value


def _scrub(obj):
    for attr in inspect(obj).mapper.column_attrs:
        v = getattr(obj, attr.key, None)
        if isinstance(v, (str, dict, list)):
            nv = clean(v)
            if nv != v:
                setattr(obj, attr.key, nv)


def _before_flush(session, flush_context, instances):
    for obj in list(session.new) + list(session.dirty):
        _scrub(obj)


def install():
    if not event.contains(Session, "before_flush", _before_flush):
        event.listen(Session, "before_flush", _before_flush)
