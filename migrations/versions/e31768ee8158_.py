"""empty message

Revision ID: e31768ee8158
Revises: 
Create Date: 2025-12-12 10:24:30.361951

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e31768ee8158'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # 1. user (no dependencies)
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=150), nullable=False),
    sa.Column('email', sa.String(length=150), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('profile_pic', sa.String(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )

    # 2. token_blocklist (no dependencies)
    op.create_table('token_blocklist',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('jti', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_token_blocklist_jti'), 'token_blocklist', ['jti'], unique=False)

    # 3. scam_report (depends on user)
    op.create_table('scam_report',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('message', sa.String(length=500), nullable=False),
    sa.Column('suspicious', sa.Boolean(), nullable=True),
    sa.Column('screenshot', sa.String(length=255), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )

    # 4. mpesa_upload (depends on user)
    op.create_table('m_pesa_upload',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('filename', sa.String(length=255), nullable=True),
    sa.Column('result_code', sa.Integer(), nullable=True),
    sa.Column('result_desc', sa.String(length=255), nullable=True),
    sa.Column('amount', sa.Float(), nullable=True),
    sa.Column('receipt', sa.String(length=50), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )

    # 5. fraud_contact (depends on user)
    op.create_table('fraud_contact',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=150), nullable=True),
    sa.Column('phone', sa.String(length=20), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )

    # 6. transaction (depends on user)
    op.create_table('transaction',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('amount', sa.Float(), nullable=False),
    sa.Column('phone_number', sa.String(length=30), nullable=False),
    sa.Column('reference', sa.String(length=100), nullable=True),
    sa.Column('status', sa.String(length=50), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )

    # 7. suspicious_event (depends on user + transaction)
    op.create_table('suspicious_event',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('transaction_id', sa.Integer(), nullable=True),
    sa.Column('reason', sa.String(length=255), nullable=False),
    sa.Column('severity', sa.String(length=20), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['transaction_id'], ['transaction.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )

    # 8. audit_log (depends on user)
    op.create_table('audit_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('action', sa.String(length=255), nullable=False),
    sa.Column('details', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('audit_log')
    op.drop_table('suspicious_event')
    op.drop_table('transaction')
    op.drop_table('fraud_contact')
    op.drop_table('m_pesa_upload')
    op.drop_table('scam_report')
    op.drop_index(op.f('ix_token_blocklist_jti'), table_name='token_blocklist')
    op.drop_table('token_blocklist')
    op.drop_table('user')