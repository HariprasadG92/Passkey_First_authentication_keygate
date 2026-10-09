"""ORM model registry.

Import every model module here so ``Base.metadata`` is complete for Alembic autogenerate.
Models are added from Phase 1 onwards.
"""

from keygate.db.base import Base

__all__ = ["Base"]
