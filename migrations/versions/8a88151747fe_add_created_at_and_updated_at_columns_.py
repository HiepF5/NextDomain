"""Add created_at and updated_at columns to Domain model

Revision ID: 8a88151747fe
Revises: f1cf49244d61
Create Date: 2024-11-12 06:42:42.343750

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '8a88151747fe'
down_revision = 'f1cf49244d61'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    
    op.add_column('domain', sa.Column('updated_at', sa.DateTime(), nullable=True))
   
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###

    op.drop_column('domain', 'updated_at')
    