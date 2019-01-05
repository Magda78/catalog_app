#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, redirect, jsonify, \
    url_for, flash
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import SingletonThreadPool
from database_setup import Base, Category, MenuItem, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web'
                                                                ]['client_id']
APPLICATION_NAME = 'CatalogApp'
engine = create_engine('sqlite:///cataloga.db',
                       connect_args={'check_same_thread': False}, echo=True)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token

@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase +
                    string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():

    # Validate state token

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'
                                            ), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

# Obtain authorization code

    code = request.data

    try:

        # Upgrade the authorization code into a credentials object

        oauth_flow = flow_from_clientsecrets('client_secrets.json',
                                             scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = \
            make_response(json.dumps('Failed to upgrade the \
                                    authorization code.'
                                     ), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

# Check that the access token is valid.

    access_token = credentials.access_token
    url = \
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' \
        % access_token
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = \
            make_response(json.dumps("Token's user ID doesn't \
                                    match given user ID."
                                     ), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.

    if result['issued_to'] != CLIENT_ID:
        response = \
           make_response(json.dumps("Token's client ID does not match app's."
                                    ), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = \
            make_response(json.dumps('Current user is already connected.'
                                     ), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info

    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

# See if a user exists, if it doesn't make a new one

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += \
        ' " style = "width: 300px; \
                    height: 300px; \
                    border-radius: 150px;- \
                    webkit-border-radius: 150px; \
                    -moz-border-radius: 150px;"> '
    flash('you are now logged in as %s' % login_session['username'])
    print 'done!'
    return output


# User Helper Functions

def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email'
                                                             ]).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = \
            make_response(json.dumps('Current user not connected.'),
                          401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
        % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'
                                            ), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = \
            make_response(json.dumps('Failed to revoke token for \
                                      given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# API Endpoint

# All categories
@app.route('/JSON')
@app.route('/catalog/JSON')
def showCategoryJSON():
    categories = session.query(Category).all()
    return jsonify(category=[c.serialize for c in categories])


# All items in the category
@app.route('/catalog/<category_name>/JSON')
@app.route('/catalog/<category_name>/menu/JSON')
def showMenuJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(MenuItem).filter_by(
        category=category).all()
    return jsonify(MenuItems=[i.serialize for i in items])


# Specific item

@app.route('/catalog/<category_name>/menu/<menu_name>/descryption/JSON')
def showdescryptionJSON(category_name, menu_name):
    item = session.query(MenuItem).filter_by(name=menu_name).first()
    return jsonify(itme=item.serialize)


# Show all categories

@app.route('/')
@app.route('/catalog/')
def showCategory():
    categories = session.query(Category).all()
    items = session.query(MenuItem).order_by(desc(MenuItem.id)).limit(4)

    if 'username' not in login_session:
        return render_template('publiccategory.html', categories=categories)
    else:
        return render_template('category.html',
                               categories=categories,
                               items=items)


# Create a new category

@app.route('/catalog/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'],
                               user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        return redirect(url_for('showCategory'))
    else:
        return render_template('newCategory.html')


# Edit category

@app.route('/catalog/<category_name>/edit/', methods=['GET', 'POST'])
def editCategory(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    editCategory = session.query(
        Category).filter_by(name=category_name).first()
    if editCategory.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized \
                                                    to edit this category. \
                                                    Please create your own \
                                                    category in order \
                                                    to edit.');} \
                </script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editCategory.name = request.form['name']
            return redirect(url_for('showCategory'))
    else:
        return render_template(
            'editCategory.html', category=editCategory)


# Delete category

@app.route('/catalog/<category_name>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    categoryToDelete = session.query(
        Category).filter_by(name=category_name).first()
    if categoryToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized \
                                                    to delete this category. \
                                                    Please create your own \
                                                    category in order to \
                                                    delete.');} \
                    </script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        return redirect(
            url_for('showCategory', category_name=category_name))
    else:
        return render_template(
            'deleteCategory.html', category=categoryToDelete)


# Show items in the category
@app.route('/catalog/<category_name>/')
@app.route('/catalog/<category_name>/menu/')
def showMenu(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(MenuItem).filter_by(
        category=category).all()
    if 'username' not in login_session:
        return render_template('publicmenu.html', category=category,
                               items=items)
    else:
        return render_template('menuItems.html',
                               items=items,
                               category=category)


# Show descryption of the item

@app.route('/catalog/<category_name>/menu/<menu_name>/descryption/')
def showdescryption(category_name, menu_name):
    if 'username' not in login_session:
        return redirect('/login')
    item = session.query(MenuItem).filter_by(name=menu_name).first()
    category = \
        session.query(Category).filter_by(name=category_name).one()
    return render_template('itemdescription.html', item=item,
                           category=category, menu_name=menu_name)


# Edit item description

@app.route('/catalog/<category_name>/<menu_name>/descryption/edit',
           methods=['GET', 'POST'])
def editMenuDes(category_name, menu_name):
    if 'username' not in login_session:
        return redirect('/login')
    editedDes = session.query(MenuItem).filter_by(name=menu_name).one()

    category = \
        session.query(Category).filter_by(name=category_name).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not authorized \
                                                    to edit this item \
                                                    description.');} \
                    </script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['description']:
            editedDes.description = request.form['description']
        session.add(editedDes)
        session.commit()
        return redirect(url_for('showdescryption',
                                category_name=category_name,
                                menu_name=menu_name))
    else:

        return render_template('editDescription.html',
                               category_name=category_name,
                               menu_name=menu_name,
                               item=editedDes)

# Edit item


@app.route('/catalog/<category_name>/menu/<menu_name>/edit',
           methods=['GET', 'POST'])
def editMenuItem(category_name, menu_name):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(MenuItem).filter_by(name=menu_name).one()

    category = \
        session.query(Category).filter_by(name=category_name).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not authorized \
                                                    to edit items in this \
                                                    category.');} \
                    </script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['image']:
            editedItem.price = request.form['image']

        session.add(editedItem)
        session.commit()
        return redirect(url_for('showMenu', category_name=category_name))
    else:

        return render_template('editmenuitem.html',
                               category_name=category_name,
                               menu_name=menu_name,
                               item=editedItem)


# Delete item
@app.route('/catalog/<category_name>/menu/<menu_name>/delete',
           methods=['GET', 'POST'])
def deleteMenuItem(category_name, menu_name):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(MenuItem).filter_by(name=menu_name).one()

    category = \
        session.query(Category).filter_by(name=category_name).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not authorized \
                                                    to delete menu items in \
                                                    this category. \
                                                    Please create your own \
                                                    category in order to \
                                                    delete items.');}  \
                    </script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for('showMenu', category_name=category_name))
    else:
        return render_template('deletemenuitem.html',
                               category_name=category_name,
                               menu_name=menu_name,
                               item=itemToDelete)


# New item
@app.route(
    '/catalog/<category_name>/menu/new/', methods=['GET', 'POST'])
def newMenuItem(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(name=category_name).one()

    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not authorized \
                                                    to add menu items to this \
                                                    category. Please create \
                                                    your own category in \
                                                    order to add items.');} \
                    </script><body onload='myFunction()''>"
    if request.method == 'POST':
        newItem = MenuItem(name=request.form['name'], description=request.form[
                           'description'], image=request.form['image'],
                           category=category)
        session.add(newItem)
        session.commit()

        return redirect(url_for('showMenu', category_name=category_name))
    else:
        return render_template('newItem.html', category_name=category_name)

    return render_template('newMenuItem.html', categry=category)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
