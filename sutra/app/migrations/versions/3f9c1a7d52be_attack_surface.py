"""attack surface zones and rule hit counts

Revision ID: 3f9c1a7d52be
Revises: e1313cf02368
Create Date: 2026-10-13 14:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3f9c1a7d52be'
down_revision: Union[str, Sequence[str], None] = 'e1313cf02368'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('attack_zones',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('kind', sa.String(length=12), nullable=False),
    sa.Column('cidrs', sa.JSON(), nullable=False),
    sa.Column('updated_by', sa.Integer(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('attack_hits',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('device_id', sa.Integer(), nullable=False),
    sa.Column('source_format', sa.String(length=24), nullable=False),
    sa.Column('rules', sa.JSON(), nullable=False),
    sa.Column('loaded_at', sa.DateTime(), nullable=False),
    sa.Column('loaded_by', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['device_id'], ['network_devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['loaded_by'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('device_id')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('attack_hits')
    op.drop_table('attack_zones')
