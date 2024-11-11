"""update_is_create_user is_domain_free

Revision ID: bd397cd6a720
Revises: b24bf17725d2
Create Date: 2024-11-08 08:05:41.135339

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'bd397cd6a720'
down_revision = 'b24bf17725d2'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index('session_id', table_name='sessions')
    op.drop_table('sessions')
    op.add_column('domain', sa.Column('is_user_created', sa.Integer(), nullable=True))
    op.add_column('domain', sa.Column('is_domain_free', sa.Integer(), nullable=True))
    op.alter_column('domain', 'type',
               existing_type=mysql.VARCHAR(length=8),
               nullable=False)
    op.alter_column('user', 'confirmed',
               existing_type=mysql.TINYINT(display_width=1),
               type_=sa.SmallInteger(),
               existing_nullable=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('user', 'confirmed',
               existing_type=sa.SmallInteger(),
               type_=mysql.TINYINT(display_width=1),
               existing_nullable=False)
    op.alter_column('domain', 'type',
               existing_type=mysql.VARCHAR(length=8),
               nullable=True)
    op.drop_column('domain', 'is_domain_free')
    op.drop_column('domain', 'is_user_created')
    op.create_table('sessions',
    sa.Column('id', mysql.INTEGER(display_width=11), autoincrement=True, nullable=False),
    sa.Column('session_id', mysql.VARCHAR(length=255), nullable=True),
    sa.Column('data', sa.BLOB(), nullable=True),
    sa.Column('expiry', mysql.DATETIME(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    mysql_collate='utf8mb4_general_ci',
    mysql_default_charset='utf8mb4',
    mysql_engine='InnoDB'
    )
    op.create_index('session_id', 'sessions', ['session_id'], unique=True)
    # ### end Alembic commands ###
