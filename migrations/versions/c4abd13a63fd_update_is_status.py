"""update is status

Revision ID: c4abd13a63fd
Revises: bd397cd6a720
Create Date: 2024-11-11 10:10:56.524680

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'c4abd13a63fd'
down_revision = 'bd397cd6a720'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('domain', sa.Column('status', sa.String(length=50), nullable=True))

def downgrade():
    op.drop_column('domain', 'status')
