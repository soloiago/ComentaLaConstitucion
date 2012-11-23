import cgi
import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = False)

secret = 'loquesea'


####################### USEFUL FUNCTIONS ######################
def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

def getComments(sortedComments, numero, id, i):
	comments = Comment.gql("WHERE numero = %s AND replyComment = %s ORDER by created" % (numero, id))
	for c in comments:
		commentMargin={}
		commentMargin['comment'] = c
		commentMargin['margin'] = (i+1)*20
		sortedComments.append(commentMargin)
		getComments(sortedComments, numero, c.get_id(), i+1)    
##################### END USEFUL FUNCTIONS ####################


####################### USEFUL CLASSES ######################
class ClcHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		params['view'] = self.view
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))
		self.view = False


class Signup(ClcHandler):
	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username,
					  email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup-form.html', **params)
		else:
			self.done()

	def done(self, *a, **kw):
		raise NotImplementedError
##################### END USEFUL CLASSES ####################


########################### MODELS ###########################
class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	def get_id(self):
		return self.key().id()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

class Voto(db.Model):
	articulo = db.IntegerProperty()
	userName = db.StringProperty()
	nota = db.IntegerProperty()

class Comment(db.Model):
	comment = db.TextProperty()
	name = db.StringProperty()
	numero = db.IntegerProperty()
	replyComment = db.IntegerProperty()
	created = db.DateTimeProperty(auto_now_add = True)

	def get_id(self):
		return self.key().id()

class Articulo(db.Model):
	articulo = db.TextProperty()
	titulo = db.StringProperty()
	capitulo = db.StringProperty()
	seccion = db.StringProperty()
	numero = db.IntegerProperty()

	def get_id(self):
		return self.key().id()
######################### END MODELS #########################


######################### CONTROLLERS ########################
class Register(Signup):
	def done(self):
		#make sure the user doesn't already exist
		u = User.by_name(self.username)
		if u:
			msg = 'That user already exists.'
			self.render('signup-form.html', error_username = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login(u)
			self.redirect('/')

class Login(ClcHandler):
	def get(self):
		self.render('login-form.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username, password)
		if u:
			self.login(u)
			self.redirect('/')
		else:
			msg = 'Invalid login'
			self.render('login-form.html', error = msg)

class Logout(ClcHandler):
	def get(self):
		self.logout()
		self.redirect('/')


class Clc(ClcHandler):
	def get(self):
		comments = Comment.all()

		dictComment = {}

		for c in comments:
			if str(c.numero) in dictComment:
				numComments = dictComment[str(c.numero)]
				dictComment[str(c.numero)] = numComments + 1
			else:
				dictComment[str(c.numero)] = 1

		aux = 0
		mostCommentedArticle = 0

		for key in dictComment:
			if int(dictComment[key]) > aux:
				aux = dictComment[key]
				mostCommentedArticle = key
		
		if self.user:
			user = self.user
		else:
			user = ""
			
		params = dict(mostCommentedArticle = mostCommentedArticle, user = user)
		self.render('index.html', **params)


class SearchArticulos(ClcHandler):
	def post(self):
		q = self.request.get('q')
		articulos = Articulo.all(keys_only=False)

		articulosMatched = []

		for articulo in articulos:
			if re.search(q, articulo.articulo):
				articulosMatched.append(articulo)

		self.render('result.html', articulosMatched = articulosMatched)


class ManageDb(ClcHandler):
	def get(self):
		articulos = Articulo.gql("ORDER BY numero DESC")
		params = dict(articulos = articulos)
		self.render('manageDb.html', **params)

	def post(self):
		articulo = self.request.get('articulo')
		titulo = self.request.get('titulo')
		capitulo = self.request.get('capitulo')
		seccion = self.request.get('seccion')
		numero = int(self.request.get('numero'))

		articulo = Articulo(articulo = articulo, titulo = titulo, capitulo = capitulo, seccion = seccion, numero = numero).put()
		self.redirect("/manageDb")


class ShowArticulo(ClcHandler):
	def get(self):
		numero = self.request.get('n')
		articulo = Articulo.gql("WHERE numero = %s" % numero).get()
		comments = Comment.gql("WHERE numero = %s AND replyComment = 0 ORDER by created" % numero)

		sortedComments = []
			
		for c in comments:
			commentMargin={}
			commentMargin['comment'] = c
			commentMargin['margin'] = 0
			sortedComments.append(commentMargin)
			getComments(sortedComments, numero, c.get_id(), 0)
						
		nota = {}
		votos = Voto.gql("WHERE nota = 0 AND articulo=%s" % numero)
		nota['a'] = votos.count()
		votos = Voto.gql("WHERE nota = 1 AND articulo=%s" % numero)
		nota['b'] = votos.count()
		votos = Voto.gql("WHERE nota = 2 AND articulo=%s" % numero)
		nota['c'] = votos.count()

		if self.user:
			voto = Voto.gql("WHERE userName = '%s' AND articulo=%s" % (self.user.name, numero))
			voto = voto.get()

			if voto:
				params = dict(articulo = articulo, numero = numero, comments = sortedComments, voto = voto.nota, nota = nota)   
			else:
				params = dict(articulo = articulo, numero = numero, comments = sortedComments, nota = nota)
		else:
			params = dict(articulo = articulo, numero = numero, comments = sortedComments, nota = nota)
			
		self.render('articulo.html', **params)


class ShowUserHistory(ClcHandler):
	def get(self):
		name = self.request.get('id')
		comments = Comment.gql("WHERE name = '%s' ORDER by created" % name)

		self.render('user.html', comments = comments)


class InsertarComentario(ClcHandler):
	def post(self):
		comment = self.request.get('comment')
		numero = int(self.request.get('numero'))
		replyComment = int(self.request.get('replyComment'))

		Comment(comment = comment, name = self.user.name, numero = numero, replyComment = replyComment).put()
		
		self.redirect("/art?n=" + str(numero))


class Votar(ClcHandler):
	def post(self):
		numero = int(self.request.get('numero'))
		opinion = int(self.request.get('opinion'))

		voto = Voto.gql("WHERE userName = '%s' AND articulo=%s" % (self.user.name, numero))
		voto = voto.get()
		
		if voto:
			voto.nota = opinion
			voto.put()
		else:
			Voto(articulo = numero, userName = self.user.name, nota = opinion).put()
	
		self.redirect("/art?n=" + str(numero))
####################### END CONTROLLERS ######################


app = webapp2.WSGIApplication([('/signup', Register),
							   ('/login', Login),
							   ('/logout', Logout),
							   ('/', Clc),
							   ('/search', SearchArticulos),
							   ('/manageDb', ManageDb),
							   ('/art', ShowArticulo),
							   ('/user', ShowUserHistory),			
							   ('/insertComment', InsertarComentario),
							   ('/votar', Votar),
							   ],
							  debug=True)
