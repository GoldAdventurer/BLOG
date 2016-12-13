import os
import re
from string import letters
import random
import hashlib
import hmac

import jinja2
import webapp2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

SECRET = "iamsosecret"


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    """
    The class Bloghandler has functions which helps display templates
    and handles cookies requests.
    """
    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def set_secure_cookie(self, name, val):
        """
        adds a cookie
        """
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s = %s; Path = /' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """
        returns the cookie value if the cookie value is secure
        """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """
        Set cookie after login
        """
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """
        Resets cookie after logout
        """
        self.response.headers.add_header('Set-Cookie', 'user_id = ; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def make_salt(length=5):
    """
    creates a salt used for cookie
    """
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    """
    makes secure hash and salt
    """
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name+pw+salt).hexdigest()
    return "%s,%s" % (salt, h)


def valid_pw(name, password, h):
    """
    check password validity
    """
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User (db.Model):
    """
    Class User: creates instances of users with the following attributes
        name: user's name. The name is required
        pw_hash : user's hashed password.
            The password is hashed for security reasons.
            The password is required.
        email: user's email (not required)
    """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


def valid_username(username):
    """
    function valid_username:
    It checks the username's validity
    """
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    """
    function valid_password:
    It checks the password's validity
    """
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def valid_email(email):
    """
    function valid_email:
    It checks the email's validity
    """
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+.[\S]+$')
    return not email or EMAIL_RE.match(email)


class Unit3Welcome(BlogHandler):
    """
    class WelcomeHandler: handler related to the welcome page
    Returns a welcome page with the username on it.
    """
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name,
                        usernameHeader=self.user.name)
        else:
            self.redirect('/signup')


class SignupHandler(BlogHandler):
    """
    class SignupHandler: handler related to the signup page
    Returns a signup page (get method) and post the data on the signup page
    (username, hashed password) to the database (post methods).
    The Post method displays and error message if the login credentials
    are incorrect.
    """
    def get(self):
        if not self.user:
            self.render('signup.html', usernameHeader="")
        else:
            msg = "You are already logged in, %s" % self.user.name
            self.render('signup.html', msg=msg, usernameHeader=self.user.name)

    def post(self):
        have_error = False
        # retrieval of data entered: username, email,
        # and password (entered twice))
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")

        params = {}
        params['email'] = self.email
        params['username'] = self.username
        # check on username, password, email
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
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise notImplementedError


class RegisterHandler(SignupHandler):
    """
    class RegisterHandler:
    The class inherits from the class SignupHandler.
    It contains a function "done" which checks that the user doesn't already
    exist in the database, creates a user, sets the cookie and then redirect
    the user to the welcome page.
    """
    def done(self):
        # checks that the user doesn't exist
        u = User.by_name(self.username)
        if u:
            msg = "That user already exists."
            self.render('signup.html', error_username=msg, usernameHeader="")
        else:
            # create user
            u = User.register(self.username, self.password, self.email)
            # store user in database
            u.put()

            # set the cookie
            self.login(u)
            user = self.username
            # redirect to welcome page
            self.redirect('welcome', usernameHeader=self)


class Login(BlogHandler):
    """
    Class Login:
    The get method displays the login template. The post method checks
    the login and password's validity. If the login information is valid,
    the user is redirected to the welcome page. If not, the user is invited
    to reenter the login information. A red error message is displayed
    on the same page.
    """
    def get(self):
        if not self.user:
            self.render('login.html', usernameHeader="")
        else:
            msg = "You are already logged in, %s" % self.user.name
            self.render('login.html', msg=msg)

    def post(self):
        self.username = self.request.get("username")
        self.password = self.request.get("password")

        params = {}
        params['password'] = self.password
        params['username'] = self.username
        # checks the existence of a user and the validity of the password
        u = User.by_name(self.username)
        if u and valid_pw(self.username, self.password, u.pw_hash):
            # sets the cookie
            self.login(u)
            # variable user is used to change the header menu
            user = self.username
            # redirect to welcome page
            self.redirect('welcome')
        else:
            # if the credentials are invalid, an error message is
            # displayed on the login page and the user has to reenter login
            # information.
            params['error_login'] = "Invalid login."
            params['usernameHeader'] = ""
            self.render('login.html', **params)


class Logout(BlogHandler):
    """
    Class logout:
        Resets the cookie and redirects the user to the signup page.
    """
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/signup')


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    """
    class Post:
        Creates one instances for each post with the following attributes:
            subject: blog's subject (required)
            content: blog's content (required)
            last_modified: Blog's date and time of creation
               It is automatically created.
            author: blog's author (required)
    """
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty(required=True)

    def render(self):
        self.update_post()
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class BlogFront(BlogHandler):
    """
    class BlogFront:
        displays all posts to non-logged in users.
    """
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post " +
                            "ORDER BY last_modified DESC")
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    """
    class Postpage:
        Displays a confirmation page with the new post displayed in it.
    """
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post, usernameHeader=self.user.name)


class NewPost(BlogHandler):
    """
    class NewPost:
        Get method: Displays a new page to create a new post after checking
        that user is logged in and cookie is valid.
        Post method: ckeck that all attributes are valid and creates a new
        instance of the class Post. If the attributes are incomplete,
        an error message is displayed to prompt the user to provide all
        required fields.
    """
    def get(self):
        uid = self.read_secure_cookie('user_id')
        if self.user:
            if User.by_id(int(uid)).name == self.user.name:
                self.render('newpost.html', usernameHeader=self.user.name)
            else:
                self.redirect('/login')
        else:
            self.redirect('/login')

    def post(self):
        uid = self.read_secure_cookie('user_id')
        if self.user:
            if User.by_id(int(uid)).name == self.user.name:
                subject = self.request.get('subject')
                content = self.request.get('content')
                uid = self.read_secure_cookie('user_id')
                author = User.by_id(int(uid)).name

                if subject and content and author:
                    p = Post(parent=blog_key(), subject=subject, content=content,
                             author=author)
                    p.put()
                    self.redirect('/blog/%s' % str(p.key().id()))
                else:
                    error = "subject and content, please!"
                    self.render('newpost.html', subject=subject, content=content,
                                error=error, usernameHeader=self.user.name)
            else:
                self.redirect('/login')
        else:
            self.redirect('/login')


class One_User_Post(BlogHandler):
    def get(self):
        if self.user:
            u = User.by_name(self.user.name)
            posts = db.GqlQuery("SELECT * FROM Post " +
                                "ORDER BY last_modified DESC")
            # search for posts from that users
            one_user_posts = db.GqlQuery("SELECT * FROM Post " +
                                         "WHERE author= :1 " +
                                         "ORDER BY last_modified DESC", u.name)
            # redirect to blog page for logged in user
            self.render('user_front.html', posts=posts,
                        one_user_posts=one_user_posts,
                        usernameHeader=self.user.name)
            # redirect to blog page for non logged-in users
        else:
            self.redirect('/blog')

    def post(self):
        post_id = self.request.get("p_id_nb")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = db.get(key)
        if post_id:
            self.redirect('/blog_edit/%s' % str(p.key().id()))
        else:
            self.error(404)


class Comment(db.Model):
    """
    class comments is used to stores comments for all posts.
    Each instance has five attributes:
        post_id: the ID of the post
        commentor: name of the person who wrote the comment
        last_modified: date and time when the post is saved.A It is
                automatically populated.
        comment: text content
        like: boolean variable that records whether the user liked the post or
                not.
    """
    post = db.ReferenceProperty(Post, collection_name="comments")
    post_id = db.StringProperty(required=True)
    commentor = db.StringProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    comment = db.TextProperty(required=True)
    like = db.BooleanProperty()

    def render(self):
        """
        Function render: the function maintains line breaks.
        argument: self
        """
        self._render_text = self.comment.replace('\n', '<br>')


class CommentPost(BlogHandler):
    """
    class CommentPost:
    This class contains a get method and a post method.
    This class handles the display of previous comments related to a post and
    of a textarea that can create new comments or help edit old comments.
    The user cannot comment on his posts, cannot delete other users' comments
    and can edit/delete his own comments.
    """
    def get(self):
        # retrieval of post
        postid = self.request.get("postid")
        key = db.Key.from_path('Post', int(postid), parent=blog_key())
        p = db.get(key)
        u = self.user
        if p:
            error = ""
        # retrieval of the comment ID
        commentid = self.request.get("commentid")
        # retrieval of comment corresponding to comment ID
        if commentid:
            key_c = db.Key.from_path('Comment', int(commentid),
                                     parent=blog_key())
            c = db.get(key_c)
            comment = c.comment
        else:
            comment = ""
        # Retrieval of all comments related to a post if the user is not
        # the post's author, and display of an error message if the user is
        # the post's author.
        if u.name != p.author:
            comments = db.GqlQuery("SELECT * FROM Comment " +
                                   "WHERE post_id= :1 " +
                                   "ORDER BY last_modified DESC", postid)
            self.render('comment.html', comments=comments, p=p,
                        comment=comment, usernameHeader=self.user.name)
        else:
            msg = "You cannot comment your own posts!"
            self.render('user_front.html', msg=msg,
                        usernameHeader=self.user.name)

    def post(self):
        # retrieval of parameters
        postid = self.request.get("postid")
        commentid = self.request.get("commentid")
        checkbox = self.request.get('like')
        if checkbox == "checked":
            like = True
        else:
            like = False
        # If the user clicks on "submit" and the comment already exists,
        # it is updated,
        if self.request.get('button') == "Submit":
            if commentid:
                key_c = db.Key.from_path('Comment', int(commentid),
                                         parent=blog_key())
                c = db.get(key_c)
                c.comment = self.request.get('comment')
                c.like = like
                c.put()
                key = db.Key.from_path('Post', int(postid), parent=blog_key())
                p = db.get(key)
                msg = "Your changes were saved!"
                like = checkbox
                self.render('comment.html', p=p, like=like, comment=c.comment,
                            msg=msg)
        # if the user clicks on "submit" and there is no comment,
        # the application creates a new instance from the class Comment.
            else:
                commentor = self.user.name
                comment = self.request.get('comment')
                if comment or like:
                    c = Comment(parent=blog_key(), post_id=postid,
                                commentor=commentor,
                                comment=comment, like=like)
                    c.put()
                    key = db.Key.from_path('Post', int(postid),
                                           parent=blog_key())
                    p = db.get(key)
                    msg = "Your changes were saved!"
                    like = checkbox
                    self.render('comment.html', p=p, like=like,
                                comment=comment, msg=msg)
        # if the user clicks on the button "Return to Blogs", the user is
        # redirected to the blog page.
        elif self.request.get('button') == "Return to Blogs":
            self.redirect('/blog_my_posts')


class DeleteComment(BlogHandler):
    """
    Class DeleteComment:
    This class redirects the user to a page where the details of the comments
    are displayed. The user can delete/edit his own comments only.
    The user is asked to confirm the deletion of the comment before the comment
    is deleted from the database.
    """
    def get(self):
        # retrieval of parameters
        commentid = self.request.get("commentid")
        key = db.Key.from_path('Comment', int(commentid), parent=blog_key())
        if key:
            c = db.get(key)
            # display of an error message if the user is not the comment's
            #  author
            if c.commentor != self.user.name:
                msg = "You can only delete your comments!"
                self.render('user_front.html', msg=msg, username=self.user.name)
            # redirection to a form where the comment's details are displayed
            else:
                self.render('deletecomment.html', c=c, commentid=commentid,
                            usernameHeader=self.user.name)
        else:
            self.render('user_front.html', msg=msg, username=self.user.name)

    def post(self):
        # retrieval of parameters
        commentid = self.request.get("commentid")
        key = db.Key.from_path('Comment', int(commentid), parent=blog_key())
        if key:
            c = db.get(key)
            # display of an error message of the user is not the comment's
            # author
            if c.commentor != self.user.name:
                msg = "You can only delete your comments!"
                self.render('user_front.html', msg=msg,
                            usernameHeader=self.user.name)
            else:
                # deletion of post if the user clicks on the "Delete" button
                if self.request.get('button') == 'Delete':
                    c.delete()
                    self.redirect('/blog_my_posts')
                # redirection to the editing page if the user clicks on the
                # "Edit Only" button
                elif self.request.get('button') == 'Edit Only':
                    self.redirect('/blog_comment/?commentid=%s&?postid=%s'
                              % (str(c.key().id()), postid))
        else:
            self.render('user_front.html', msg=msg, username=self.user.name)

class EditComment(BlogHandler):
    """
    class EditComment:
    This class redirects the user to a page where the details of the comment
    are displayed. The user can edit his own posts only.
    """
    def get(self):
        # retrieval of post
        postid = self.request.get("postid")
        key = db.Key.from_path('Post', int(postid), parent=blog_key())
        # variable initialization. Each variable indicates whether
        # the ID is valid
        valid_P_ID = False
        valid_C_ID = False
        if key:
            p = db.get(key)
            u = User.by_name(self.user.name)
            valid_P_ID = True
        # retrieval of the comment ID
        commentid = self.request.get("commentid")
        # retrieval of comment corresponding to comment ID
        if commentid:
            key_c = db.Key.from_path('Comment', int(commentid),
                                     parent=blog_key())
            c = db.get(key_c)
            if c.commentor == self.user:
                comment = c.comment
                valid_C_ID = True
        else:
            comment = ""
        # Retrieval of all comments related to a post if the user is not
        # the post's author, and display of an error message if the user is
        # the post's author.
        if self.user.name == c.commentor and supplied_C_ID and supplied_P_ID:
            self.render('comment_edit.html', c=c, p=p, comment=comment,
                        usernameHeader=self.user.name)
        elif self.user.name != c.commentor and supplied_C_ID and supplied_P_ID:
            msg = "You cannot edit other users' comments!"
            self.render('user_front.html', msg=msg,
                        usernameHeader=self.user.name)
        else:
            msg = ""
            self.render('user_front.html', msg=msg,
                        usernameHeader=self.user.name)

    def post(self):
        # retrieval of parameters
        postid = self.request.get("postid")
        commentid = self.request.get("commentid")
        checkbox = self.request.get('like')
        # boolean variables initialization
        valid_C_ID = False
        valid_P_ID =  False
        if checkbox == "checked":
            like = True
        else:
            like = False
        # If the user clicks on "submit" and the comment already exist,
        # it is updated,
        if self.request.get('button') == "Submit":
            if commentid and postid:
                key_c = db.Key.from_path('Comment', int(commentid),
                                         parent=blog_key())
                if key_c
                c = db.get(key_c)
                c.comment = self.request.get('comment')
                c.like = like
                c.put()
                key = db.Key.from_path('Post', int(postid), parent=blog_key())
                if key:
                    p = db.get(key)
                    msg = "Your changes were saved!"
                    like = checkbox
                    self.render('comment.html', p=p, like=like, comment=c.comment,
                                msg=msg, usernameHeader=self.user.name)
                else:
                    self.redirect('/blog_my_posts')
        # if the user clicks on "submit" and there is no comment, the
        # application creates a new instance from the class Comment.
            else:
                commentor = self.user.name
                comment = self.request.get('comment')
                if comment or like:
                    c = Comment(parent=blog_key(), post_id=postid,
                                commentor=commentor,
                                comment=comment, like=like)
                    c.put()
                    key = db.Key.from_path('Post', int(postid),
                                           parent=blog_key())
                    p = db.get(key)
                    msg = "Your changes were saved!"
                    like = checkbox
                    self.render('comment.html', p=p, like=like,
                                comment=comment, msg=msg)
        # if the user clicks on the button "Return to Blogs", the user is
        # redirected to the blog page.
        elif self.request.get('button') == "Return to Blogs":
            self.redirect('/blog_my_posts')


class EditPost(BlogHandler):
    """
    class EditPost:
    This class redirects the user to a page where the details of the post are
    displayed. The user can delete/edit his own posts only.
    The user is asked to confirm the deletion of the post before the post is
    deleted from the database.
    """
    def get(self):
        # retrieval of post ID, post details and user details
        postid = self.request.get("postid")
        if postid:
            postid = int(postid)
        key = db.Key.from_path('Post', int(postid), parent=blog_key())
        p = db.get(key)
        u = User.by_name(self.user.name)
        # display of an error message if the user is not the post's author
        if p:
            error = ""
        if u.name != p.author:
            msg = "You can only edit your posts!"
            self.render('user_front.html', msg=msg,
                        usernameHeader=self.user.name)
        # redirection to a form where the comment's details are displayed
        else:
            self.render('editpost.html', p=p, error=error, postid=postid, u=u,
                        usernameHeader=self.user.name)

    def post(self, button=None):
        # retrieval of parameters from database
        postid = self.request.get("postid")
        key = db.Key.from_path('Post', int(postid), parent=blog_key())
        if key and p.author == self.user.name:
            p = db.get(key)
            # reading of variables in form, post update and redirection to blog
            # page if the user clicks on "Submit"
            if self.request.get('button') == 'Submit':
                subject = self.request.get('subject')
                content = self.request.get('content')
                if subject and content:
                    p.subject = subject
                    p.content = content
                    p.put()
                else:
                    self.write('none')
                self.redirect('/blog_my_posts')
            # redirection to the template used to delete posts if the user clicks
            # on "Delete"
            elif self.request.get('button') == "Delete":
                self.redirect('/blog_delete_post/%s' % postid)
        else:
            self.redirect('/blog_delete_post/%s' % postid)


class DeletePost(BlogHandler):
    """
    Class DeletePost:
    This class redirects the user to a page where the details of the post are
    displayed. The user can delete/edit his own posts only.
    The user is asked to confirm the deletion of the post before the post is
    deleted from the database.
    """
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        if key:
            p = db.get(key)
            u = self.user
            # display of an error message if the user is not the post's author
            if u.name != p.author:
                msg = "You can only edit your posts!"
                self.render('user_front.html', msg=msg,
                            usernameHeader=self.user.name)
            # redirection to a form where the post's details are displayed
            else:
                self.render('deletepost.html', p=p, post_id=post_id,
                            usernameHeader=self.user.name)
        else:
            msg = ""
            self.render('user_front.html', msg=msg,
                        usernameHeader=self.user.name)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        if key:
            p = db.get(key)
            if self.user.name == p.author:
                if self.request.get('button') == 'Delete':
                    p.delete()
                    self.redirect('/blog_my_posts')
                elif self.request.get('button') == 'Edit Only':
                    self.redirect('/blog_edit/%s' % str(p.key().id()))
            else:
                self.redirect('/blog_my_posts')
        else:
            self.redirect('/blog_my_posts')


app = webapp2.WSGIApplication([('/signup', RegisterHandler),
                               ('/welcome', Unit3Welcome),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/?', BlogFront),
                               ('/blog_newpost', NewPost),
                               ('/blog_my_posts', One_User_Post),
                               ('/blog_edit/?', EditPost),
                               ('/blog_delete_post/([0-9]+)', DeletePost),
                               ('/blog_comment/?', CommentPost),
                               ('/blog_comment_edit/?', EditComment),
                               ('/comment_delete/?', DeleteComment)
                               ],
                              debug=True)
