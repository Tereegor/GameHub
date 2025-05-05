import requests
from flask import render_template, request
from data import db_session
from data.products import Products
from api.product_api import product_bp

from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask


def replenishment():
    db_session.global_init('db/product.db')
    session = db_session.create_session()
    query = session.query(Products).all()
    for item in query:
        if item.id < 9:
            item.quantity = item.quantity + 50
        elif 9 <= item.id <= 15:
            item.quantity = item.quantity + 30
        elif 16 <= item.id <= 19:
            item.quantity = item.quantity + 20
        elif item.id > 19:
            item.quantity = item.quantity + 10
    session.commit()


sched = BackgroundScheduler(daemon=True)
sched.add_job(replenishment, 'interval', minutes=5)
sched.start()

app = Flask(__name__)
app.register_blueprint(product_bp, url_prefix='/api')
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'


@app.route('/products')
def index():
    product = requests.get('http://localhost:5000/api/products').json()
    return render_template("index.html", information=product)


@app.route('/shopping_cart', methods=['GET', 'POST'])
def buy():
    product = requests.get('http://localhost:5000/api/products').json()
    print(product)
    print(int(request.form['thirteen_product']))
    return render_template('total.html', data=product, product_1=int(request.form['first_product']),
                           product_2=int(request.form['twice_product']), product_3=int(request.form['three_product']),
                           product_4=int(request.form['four_product']), product_5=int(request.form['five_product']),
                           product_6=int(request.form['six_product']), product_7=int(request.form['seven_product']),
                           product_8=int(request.form['eight_product']), product_9=int(request.form['nine_product']),
                           product_10=int(request.form['ten_product']), product_11=int(request.form['eleven_product']),
                           product_12=int(request.form['twelve_product']),
                           product_13=int(request.form['thirteen_product']),
                           product_14=int(request.form['fourteen_product']),
                           product_15=int(request.form['fifteen_product']),
                           product_16=int(request.form['sixteen_product']),
                           product_17=int(request.form['seventeen_product']),
                           product_18=int(request.form['eighteen_product']),
                           product_19=int(request.form['nineteen_product']),
                           product_20=int(request.form['twenty_product']),
                           product_21=int(request.form['twenty_one_product']),
                           product_22=int(request.form['twenty_two_product']))


@app.route('/work')
def work():
    return render_template('traning.html', title='Корзина')


def main():
    db_session.global_init('db/product.db')
    app.run()


if __name__ == '__main__':
    main()
