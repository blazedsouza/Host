"""empty message

Revision ID: ee9b3986b732
Revises: 
Create Date: 2020-12-03 15:31:09.250538

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ee9b3986b732'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('name', sa.String(length=50), nullable=False),
    sa.Column('password', sa.String(length=80), nullable=True),
    sa.PrimaryKeyConstraint('name')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user')
    # ### end Alembic commands ###
