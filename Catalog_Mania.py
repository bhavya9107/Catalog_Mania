from flask import Flask,render_template,request,url_for,redirect,flash,jsonify

app=Flask(__name__)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Category, Base, Item, User

from flask import session as login_session
import random, string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

CLIENT_ID= json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/login')
def showLogin():
    state=''.join(random.choice(string.ascii_uppercase+string.digits)for x in xrange(32))
    login_session['state']=state
    return render_template('login.html', STATE = state,login_session=login_session)

@app.route('/categories/<int:category_id>/item.json')
def jsonItem(category_id):
    category=session.query(Category).filter_by(id=category_id).one()
    items=session.query(Item).filter_by(category_id=category.id)
    return jsonify(Item=[i.serialize for i in items])

@app.route('/category.json')
def jsonCat():
    results = session.query(Category).order_by(Category.id).all()
    return jsonify(Category=[i.serialCat for i in results])

@app.route('/')
def first():
    results = session.query(Category).order_by(Category.id.desc()).limit(5).all()
    items=session.query(Item).order_by(Item.id.desc()).limit(5).all()
    creator = -1
    i = 1
    return render_template('homepage.html',items=items,results=results, i=i,login_session=login_session)

@app.route('/categories/<int:category_id>/new', methods=['GET','POST'])
def newItem(category_id):
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    else:
	   category = session.query(Category).filter_by(id = category_id).one()
	   if request.method == 'POST':
		  new_item = Item(name = request.form['name'], description = request.form['description'], category_id = category_id,user_id=category.user_id)
		  session.add(new_item)
		  session.commit()
		  flash(new_item.name+" is Created Successfully")
		  return redirect(url_for('Categories', category_id = category_id))
	   else:
		  return render_template('newItem.html', category_id = category_id,category=category,login_session=login_session)

@app.route('/categories/new', methods=['GET','POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    else:
       if request.method == 'POST':
          req = session.query(Category).filter_by(name = request.form['name']).first()
          if req :
            flash(request.form['name']+" already in usage")
            return redirect(url_for('newCategory'))
          else:
            newCat = Category(name = request.form['name'],user_id= login_session['user_id'])
            user_id= login_session['user_id']
            session.add(newCat)
            session.commit()
            flash(newCat.name+" is Created Successfully")
            return redirect(url_for('first'))
       else:
          return render_template('newcategory.html',login_session=login_session)

@app.route('/categories/<int:category_id>/<int:ItemID>/edit', methods = ['GET', 'POST'])
def editItem(category_id, ItemID):
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    editedItem = session.query(Item).filter_by(id = ItemID).one()
    category = session.query(Category).filter_by(id = category_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash(editedItem.name+" is edited Successfully")
        return redirect(url_for('Categories', category_id = category_id))
    else:
        return render_template('editItem.html', category_id = category_id, ItemID = ItemID, item = editedItem,category=category,login_session=login_session)
@app.route('/categories/<int:category_id>/delete_category/',methods=['GET','POST'])
def deleteCategory(category_id):
    category = session.query(Category).filter_by(id = category_id).one()
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    if category.user_id != login_session['user_id']:
        return '''<script>function myFunction() 
        {alert('You are not authorized to delete this category. Please create your own category in order to delete');}
        </script><body onload='myFunction()'>'''
    
    if request.method=='GET':
        return render_template('deletecategory.html', category = category,login_session=login_session)
    if request.method=='POST':
        session.delete(category)
        session.commit()
        flash(category.name+" is successfully deleted ;)")
        return redirect(url_for('first'))


@app.route('/categories/<int:category_id>/<int:item_id>/JSON')
def ItemJson(category_id,item_id):
    category=session.query(Category).filter_by(id=category_id).one()
    items=session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=items.serialize)
    
@app.route('/categories/<int:category_id>/')
def Categories(category_id):
    category=session.query(Category).filter_by(id=category_id).one()
    items=session.query(Item).filter_by(category_id=category.id)
    creator = getUserInfo(category.user_id)
    if 'username' not in login_session or creator.id!=login_session['user_id']:
        return render_template('categorypublic.html', category=category, items=items, creator=creator,login_session=login_session)
    else:
        return render_template('category.html', category=category, items=items, creator=creator,login_session=login_session)

@app.route('/categories/<int:category_id>/<int:item_id>/delete_item/',methods=['GET','POST'])
def deleteItem(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    itemToDelete = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('Categories', category_id=category.id))
    else:
        return render_template('deleteItem.html', item=itemToDelete , category_id = category.id,login_session=login_session)

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]


    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '''
    <div class="mdl-card mdl-shadow--2dp" style="padding: 12px;">
    <h3>Welcome,'''
    output += login_session['username']
    output += '!</h3>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 100px; height: 100px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"></div>'
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response=make_response(json.dumps('Invalid State parameter'),401)
        response.headers['Content-Type']='application/json'
        return response
    code=request.data
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

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['provider'] = 'google'
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    user_id=getUserID(login_session['email'])
    if not user_id:
        user_id=createUser(login_session)
    login_session['user_id']= user_id
    output = ''
    output += '''
    <div class="mdl-card mdl-shadow--2dp" style="padding: 12px;">
    <h3>Welcome,'''
    output += login_session['username']
    output += '!</h3>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 100px; height: 100px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"></div>'
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

@app.route('/gdisconnect')
def gdisconnect():
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] != '200':
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        return "no user signed-In"

# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('first'))
    else:
        flash("You were not logged in")
        return redirect(url_for('first'))

def getUserInfo(user_id):
    user=session.query(User).filter_by(id=user_id).first()
    return user

def createUser(login_session):
    newUser=User(name=login_session['username'], 
        email=login_session['email'], picture= login_session['picture'])
    session.add(newUser)
    session.commit()
    user= session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

   

#################################   App execution defination  ############################################

if __name__=='__main__':
    app.secret_key="tum manorogee ho"
    app.debug= True
    app.run(host="0.0.0.0",port=5555) 