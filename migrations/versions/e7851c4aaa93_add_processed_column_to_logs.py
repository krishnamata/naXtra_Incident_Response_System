"""Add processed column to logs

Revision ID: e7851c4aaa93
Revises: ca0c03c849fd
Create Date: 2025-08-28 08:32:50.240369

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e7851c4aaa93'
down_revision = 'ca0c03c849fd'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('logs', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                'processed', 
                sa.Boolean(),               # <-- explicit type
                nullable=False
            )
        )

def downgrade():
    with op.batch_alter_table('logs', schema=None) as batch_op:
        batch_op.drop_column('processed')


    # ### end Alembic commands ###
