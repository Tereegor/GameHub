import flask
from data import db_session
from data.products import Products

product_bp = flask.Blueprint('product_api', __name__, template_folder='templates')


@product_bp.route("/products")
def get_product():
    session = db_session.create_session()
    product = session.query(Products).all()
    return flask.jsonify({'product': ([item.to_dict(only=('id', 'article', 'price', 'quantity',
                                                          'usage_time', 'uniqueness', 'average_score')) for item in
                                       product])})
