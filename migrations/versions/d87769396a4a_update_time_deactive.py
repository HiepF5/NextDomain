"""update_time_deactive

Revision ID: d87769396a4a
Revises: 8a88151747fe
Create Date: 2024-12-10 04:26:42.233872

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'd87769396a4a'
down_revision = '8a88151747fe'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('domain', sa.Column('update_time_deactive', sa.DateTime(), nullable=True))
   
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('domain', 'update_time_deactive')
    