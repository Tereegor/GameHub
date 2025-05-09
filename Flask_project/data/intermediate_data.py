import sqlalchemy
from sqlalchemy import orm
from sqlalchemy_serializer import SerializerMixin

from .db_session import SqlAlchemyBase


class Intermediate_data(SqlAlchemyBase, SerializerMixin):
    __tablename__ = 'intermediate'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    article = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    quantity = sqlalchemy.Column(sqlalchemy.Integer, nullable=True)
