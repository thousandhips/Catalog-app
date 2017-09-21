from flask import Flask, render_template, request, redirect, \
jsonify, url_for, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item catalog App"

app = Flask(__name__)

engine = create_engine('sqlite:///categories.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Helper function for making a new user
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# Helper function for retrieving a user's info
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Helper function for getting a users id, given their email
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# JSON endpoint for all the items in a catefory
@app.route('/category/<category_name>/JSON')
def categoryListJSON(category_name):
    items = session.query(Item).filter_by(
        category_name=category_name).all()
    return jsonify(CategoryItems=[i.serialize for i in items])


# JSON endpoint for a specific item
@app.route('/category/<category_name>/<item_name>/JSON')
def catlogItemJSON(category_name, item_name):
    Menu_Item = session.query(Item).filter_by(name=item_name).one()
    return jsonify(Catalog_Item=Menu_Item.serialize)


# JSON endpoint for a list of all categories
@app.route('/categories/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


# Connect to a google account
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
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
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps
        	                     ('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


# Disconnect from google
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps
                                 ('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    print login_session['access_token']
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
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash("sucesfully logged out")
        return redirect(url_for('homePage'))
    else:
        response = make_response(json.dumps
                                 ('Failed to revoke token for given user.',
                                     400))
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('homePage'))


# Display the login page
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Display the home page
@app.route('/')
def homePage():
    categories = session.query(Category).all()
    items = session.query(Item).all()
    if items is not None:
        items.reverse()
    if 'username' not in login_session:
        return render_template('publicHomePage.html', categories=categories,
                               items=items)
    else:
        return render_template('homePage.html', categories=categories,
                               items=items, user_id=login_session['user_id'])

    return render_template('homePage.html', categories=categories, items=items)


# Show the page for a single category
@app.route('/category/<category_name>/')
@app.route('/category/<category_name>/catalog/')
def category(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    creator = getUserInfo(category.user_id)
    items = session.query(Item).filter_by(
        category_name=category.name).all()
    # Two different pages given based on login status
    if 'username' not in login_session:
        return render_template('publicCategory.html', items=items,
                               category=category, creator=creator)
    else:
        return render_template('category.html', items=items, category=category,
                               creator=creator,
                               user_id=login_session['user_id'])


# Display a catalog item
@app.route('/item/<category_name>/<item_name>/')
def item(category_name, item_name):
    item = session.query(Item).filter_by(name=item_name).one()
    return render_template('item.html', item=item)


# Create a new catalog item
@app.route('/item/new/', methods=['GET', 'POST'])
def newItem():
    # User msut be logged in to create an item
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category).all()
    # If the method is POST then process item info
    if request.method == 'POST':
        existingItem = session.query(Item). \
             filter_by(name=request.form['name']).one_or_none()
        print(existingItem)
        newItem = Item(user_id=login_session['user_id'],
                       name=request.form['name'],
                       description=request.form['description'],
                       category_name=request.form['category_name'])
        if(existingItem is None):
            session.add(newItem)
            session.commit()
            flash('%s Successfully Created' % (newItem.name))
        else:
            flash('%s Already Created' % (newItem.name))
        return redirect(url_for('homePage'))
    # If the method is not POST then get the newItem page
    else:
        return render_template('newItem.html', categories=categories)


# Edit a catalog item
@app.route('/category/<category_name>/<item_name>/edit',
           methods=['GET', 'POST'])
def editItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Item)\
        .filter_by(name=item_name).one()
    if editedItem.user_id != login_session['user_id']:
        return "<script>function myFunction() \
            {alert('You are not authorized to edit this item.'');} \
            </script><body onload='myFunction()''>"
    editedItem = session.query(Item).filter_by(name=item_name).one()
    category = session.query(Category).filter_by(name=category_name).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash('catalog Item Successfully Edited')
        return redirect(url_for('category', category_name=category_name))
    else:
        return render_template('editItem.html', category_name=category_name,
                               item_name=item_name, item=editedItem)


# Delete a catalog item
@app.route('/category/<category_name>/<item_name>/delete',
           methods=['GET', 'POST'])
def deleteItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Item).\
        filter_by(name=item_name).one()
    if editedItem.user_id != login_session['user_id']:
        return "<script>function myFunction() \
        {alert('You are not authorized to delete this item.'');} \
        </script><body onload='myFunction()''>"
    category = session.query(Category).filter_by(name=category_name).one()
    itemToDelete = session.query(Item).filter_by(name=item_name).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('catalog Item Successfully Deleted')
        return redirect(url_for('category', category_name=category_name))
    else:
        return render_template('deleteItem.html', item=itemToDelete)

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
