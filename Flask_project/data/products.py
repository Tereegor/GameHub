import sqlalchemy
from sqlalchemy import orm
from sqlalchemy_serializer import SerializerMixin

from .db_session import SqlAlchemyBase


class Products(SqlAlchemyBase, SerializerMixin):
    __tablename__ = 'products'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    article = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    price = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    quantity = sqlalchemy.Column(sqlalchemy.Integer, nullable=True)
    usage_time = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    uniqueness = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    average_score = sqlalchemy.Column(sqlalchemy.String, nullable=True)
