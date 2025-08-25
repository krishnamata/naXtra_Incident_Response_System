"""Add status column to user

Revision ID: 93651d7139c4
Revises: 769a1081231f
Create Date: 2025-08-02 11:04:35.170296

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '93651d7139c4'
down_revision = '769a1081231f'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('user', sa.Column('status', sa.String(length=20), nullable=True))

def downgrade():
    op.drop_column('user', 'status')
