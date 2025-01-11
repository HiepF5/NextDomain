"""update_key_view

Revision ID: 440228a4c856
Revises: c4abd13a63fd
Create Date: 2024-11-11 13:49:27.329424

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '440228a4c856'
down_revision = 'c4abd13a63fd'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('apikey', sa.Column('key_view', sa.String(length=255), nullable=True))

def downgrade():
    op.drop_column('apikey', 'key_view')

