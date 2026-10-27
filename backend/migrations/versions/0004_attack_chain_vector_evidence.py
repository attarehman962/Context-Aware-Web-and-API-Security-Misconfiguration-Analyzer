"""attack chain vector and evidence

Chains from config/chains.yaml (docs/chain-templates.md) store their composite
CVSS v3.1 vector and why they fired (scope unit, matched check ids per group,
satisfying context). Both nullable: chains stored before this have neither.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-27
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0004'
down_revision: str | None = '0003'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')


def upgrade() -> None:
    with op.batch_alter_table('attack_chains', schema=None) as batch_op:
        batch_op.add_column(sa.Column('composite_vector', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('evidence', _JSON, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('attack_chains', schema=None) as batch_op:
        batch_op.drop_column('evidence')
        batch_op.drop_column('composite_vector')
