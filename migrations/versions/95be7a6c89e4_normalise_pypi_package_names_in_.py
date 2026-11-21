"""normalise pypi package names in affected ranges

Revision ID: 95be7a6c89e4
Revises: a1c08cb7a9a9
Create Date: 2026-11-21 19:29:46.936273

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '95be7a6c89e4'
down_revision: Union[str, Sequence[str], None] = 'a1c08cb7a9a9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE affected_ranges
        SET package_name = lower(regexp_replace(package_name, '[-_.]+', '-', 'g'))
        WHERE ecosystem = 'PyPI'
        """
    )


def downgrade() -> None:
    # Irreversible by design: original spellings are not kept, and
    # normalised names remain valid for matching after a downgrade.
    pass
