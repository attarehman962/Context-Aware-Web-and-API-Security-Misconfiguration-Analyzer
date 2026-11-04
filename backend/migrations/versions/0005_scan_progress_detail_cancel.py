"""scan progress detail and cancel flag

``scans.progress_detail`` holds the worker's per-stage counts (crawling /
checking / scoring) for live status; ``scans.cancel_requested`` is raised by
``POST /api/scan/{id}/cancel`` and checked by the worker at every progress step.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-04
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0005'
down_revision: str | None = '0004'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')


def upgrade() -> None:
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('progress_detail', _JSON, nullable=True))
        # Server default only to backfill existing rows; the model sets False itself.
        batch_op.add_column(sa.Column('cancel_requested', sa.Boolean(), nullable=False,
                                      server_default=sa.false()))
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.alter_column('cancel_requested', server_default=None)


def downgrade() -> None:
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_column('cancel_requested')
        batch_op.drop_column('progress_detail')
