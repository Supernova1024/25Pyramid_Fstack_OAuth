# coding: utf-8
from sqlalchemy import (
    Column,
    DateTime,
    INTEGER,
    text,
    Unicode,
    UnicodeText,
)

from .meta import Base

metadata = Base.metadata


class User(Base):
    __tablename__ = "user"

    user_id = Column(Unicode(120), primary_key=True)
    user_name = Column(Unicode(120))
    user_email = Column(Unicode(120))
    user_password = Column(UnicodeText)
    user_about = Column(UnicodeText)
    user_cdate = Column(DateTime)
    user_llogin = Column(DateTime)
    user_super = Column(INTEGER, server_default=text("'0'"))
    user_active = Column(INTEGER, server_default=text("'1'"))
    user_apikey = Column(Unicode(64))
    tags = Column(UnicodeText)
    extras = Column(UnicodeText)
