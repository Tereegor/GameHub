import flask
from data import db_session
from data.intermediate_data import Intermediate_data

product_time_bp = flask.Blueprint('temporary_api', __name__, template_folder='templates')


@product_time_bp.route('/temporary')
def get_temporary():
    session = db_session.create_session()
    temporary = session.query(Intermediate_data).all()
    return flask.jsonify({'product_time': ([item.to_dict(only=('id', 'article', 'quantity',
                                                               )) for item in temporary])})
