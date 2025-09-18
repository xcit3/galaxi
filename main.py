#importing all necessary libraries/functions
from flask import Flask, redirect, render_template, request, session, flash, make_response, url_for, jsonify
from sqlalchemy import create_engine, text
from functools import wraps
import random
from random import shuffle
from hashlib import sha256
import time

#initialising web app
app = Flask(__name__)
app.secret_key = 'CvnRdyzG01qRT6PCS0ei0sZADfTWvQ6oWhUtWKbVArfySfRtlTDQZSW3iPqN4af6mk5iWH2UqUB8sLbfwMGWOqEVxvjCBJRv'
app.static_folder = 'static'

#Initialising sessions - persistent user data
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

#Image handling for the web app
app.config["UPLOAD_EXTENSIONS"] = [".jpg", ".png"]
app.config["UPLOAD_PATH"] = "image_uploads"

#Initialising database
engine = create_engine('sqlite:///database.db')
connection = engine.connect()




class Message:
    def __init__(self, sql_row):
        self.message_id = sql_row[0]
        self.content = sql_row[1]
        self.sender = sql_row[2]
        self.chat_id = sql_row[3]
        self.message_type = sql_row[4]
    
    def get_message_id(self):
        return self.message_id

    def get_content(self):
        return self.content
    
    def get_sender(self):
        return self.sender
    
    def get_chat_id(self):
        return self.chat_id
    
    def get_message_type(self):
        return self.message_type
    


class Chat:
    def __init__(self, sql_row):
        print(sql_row)
        self.chat_id = sql_row[0]
        self.members = sql_row[1].split('/')
        self.chat_name = sql_row[2]
        self.messages = self.initialise_messages()

    def get_chat_id(self):
        return self.chat_id

    def get_members(self):
        return self.members

    def get_name(self):
        return self.chat_name

    def get_messages(self):
        return self.messages

    def initialise_messages(self):
    #Takes a chat id, returns a list of all messages in the corresponding chat.
        query =  text(f"""SELECT * FROM messages where chat_id = '{self.chat_id}';""")
        result = connection.execute(query).fetchall()
        if result and result[0]:
            return [Message(i) for i in result]
        else:
            return []

    def message_count(self):
        return len(self.get_messages())

    def in_chat(self, account):
        if account.get_username() in self.get_members():
            return True
        return False



class Account:
    def __init__(self, sql_row):
        self.username = sql_row[0]
        self.password = sql_row[1]
        self.email = sql_row[2]
        self.salt = sql_row[3]
        self.followers = self.check_fandb(sql_row[4])
        self.blocked = self.check_fandb(sql_row[5])
    def get_username(self):
        return self.username
    def get_password(self):
        return self.password
    def get_email(self):
        return self.email
    def get_salt(self):
        return self.salt
    def get_followers(self):
        return self.followers
    def get_blocked(self):
        return self.blocked
    
    def check_fandb(self, value):
        if value:
            return remove_errors(value.split('/'))
        else:
            return []

    def get_chats(self):
    #Function that takes the user's session data and returns a list of the chats that they are a part of, or an empty list if they aren't in any.
        query =  text(f"""SELECT * FROM  Chats;""")
        result = connection.execute(query).fetchall()
        result = [Chat(i) for i in result]
        actual = [i for i in result if self.get_username() in i.get_members()]
        if actual:
            return actual
        else:
            return []
    
    def get_posted(self):
        query = text(f"SELECT * FROM POSTS WHERE poster='{self.get_username()}'")
        posts = [list(i) for i in connection.execute(query).fetchall()]
        for post in posts:
            interaction_count(post, 5)
            interaction_count(post, 3)
            query = text(f"""SELECT COUNT(*) FROM COMMENTS WHERE post_id = '{post[0]}'""")
            result = connection.execute(query).fetchone()
            post.append(result[0])
        return posts
    
    def get_post_count(self):
        return len(self.get_posted())
    
    def is_blocked(self, blocked):
        if blocked.get_username() in self.get_blocked():
            return True
        return False

    def is_follower(self, follower):
        if follower.get_username() in self.get_followers():
            return True
        return False

    


def sort_names(names):
#Function that takes a list of names and sorts them by length, returning them as a / separated string.
    names.sort(key=len)
    s_names = "/".join(names)
    return s_names


def not_spaces(string):
    not_empty = False
    for i in string:
        if i != ' ' and i != '  ':
            not_empty = True
    return not_empty
    



def get_chat(chat_id):
    query = text(f"Select * from Chats where chat_id = '{chat_id}'")
    result = Chat(connection.execute(query).fetchone())
    return result

def get_account(username):
    query = text(f"Select * from accounts where username = '{username}'")
    result = Account(connection.execute(query).fetchone())
    return result


def remove_errors(result):
#This function is slightly more vague but it's used to take a result from a database search that's been split and remove empty results before returning a list of the remaining results.
    good_result = []
    for i in result:
        if len(i) >= 2:
            good_result.append(i)
    return good_result








def get_posts(session, post_id=''):
    '''This function does 2 things which isn't fantastic, however they all fall under the umbrella of 'getting posts'.
- Firstly, if all inputs apart from session are left as empty, it'll retrieve up to 20 posts the user hasn't seen before,
resetting the seen posts when less than 20 posts are viewed.
- Secondly, if the 'post_id' variable is entered, it'll retrieve that specific post.
'''
    query =  text(f"""SELECT * FROM posts;""")
    posts = connection.execute(query).fetchall()
    if post_id:
        good_results = [list(post) for post in posts if post[0] == int(post_id)]
        print(good_results)
    else:
        good_results = [list(post) for post in posts if not get_account(session["account"]).is_blocked(get_account(post[1])) and not get_account(post[1]).is_blocked(get_account(session["account"]))]
    #Here, the following code only runs if there are any posts that meet the criteria, returning an empty list otherwise.
    if good_results:
        for post in good_results:
            #These 2 if statements check if the posts have been liked or disliked, adding the number of people who've liked/disliked to the end of the list or adding '0' to the end otherwise.
            interaction_count(post, 5)
            interaction_count(post, 3)
            query = text(f"""SELECT COUNT(*) FROM COMMENTS WHERE post_id = '{post[0]}'""")
            result = connection.execute(query).fetchone()
            post.append(result[0])
        if post_id:
            good_results = good_results[0]
        return good_results
    else:
        return []
    


def interaction_count(p_or_c, index):
    if p_or_c[index]:
        p_or_c.append(len(remove_errors(p_or_c[index].split('/'))))
    else:
        p_or_c.append('0')

def get_comments(post_id):
#Takes a post id, returns a list of all comments on the post.
    query = text(f"""SELECT * FROM COMMENTS WHERE post_id = "{post_id}";""")
    result = connection.execute(query).fetchall()
    if result and result[0]:
        updated_results = [list(item) for item in result]
        for comment in updated_results:
            print(comment)
            interaction_count(comment, 4)
            interaction_count(comment, 5)
            print(comment)
        print(result)
        return updated_results
    return []


def search_posts(term, session):
#This functions takes a search term and returns posts that contain the search term in their content.
    query = text(f"SELECT * FROM POSTS WHERE LOWER(content) LIKE LOWER('%{term}%')")
    result = connection.execute(query).fetchall()
    if result and result[0]:
        good_posts = []
        for post in result:
            good_posts.append(get_posts(session, post_id=post[0]))
        return good_posts
    return []

def search_users(term, session):
#This functions takes a search term and returns accounts that contain the search term in their username,as well as how many posts they've made.
    print(term)
    query = text(f"SELECT username FROM ACCOUNTS WHERE LOWER(username) LIKE LOWER('%{term}%')")
    result = connection.execute(query).fetchall()
    print(result)
    if result and result[0]:
        list_results = [get_account(item[0]) for item in result]
        return list_results
    return []

def get_interactions(thing_id, action, table):
#Takes a thing (post or comment) id, a action (like or dislike), and a table ('posts' or 'comments'), and returns all users who've done the action to the thing as a list
    query =  text(f"""SELECT {action} FROM {table} where {table[:-1]}_id = "{thing_id}";""")
    print(query)
    result = connection.execute(query).fetchone()
    if result and result[0]:
        result = result[0].split('/')
        good_result = remove_errors(result)
        return good_result
    else:
        return [] 


def login_check(wrapped):
#wrapper function that checks if a user is logged in. If not, redirects them to login page.
    @wraps(wrapped)
    def wrap(*args, **kwargs):
        try:
            if session["account"]:
                return wrapped(*args, **kwargs)
            else:
                return redirect("/login")
        except KeyError:
            session["account"] = ""
            return redirect("/login")
    return wrap


   



def has_interacted(thing_id, user, action, table):
    '''takes a thing (post, comment) id, a username, an action (like, dislike, comment) and a table(posts, comments)
    and checks if the user has done the action to the thing. Returns true/false.'''
    interacted_list = get_interactions(thing_id, action, table)
    if user in interacted_list:
        return True
    return False


def convert_breaks(array):
    new_array = []
    for i in array:
        if i == "\n":
            new_array.append("<br>")
        elif i == "\r":
            new_array.append('')
        else:
            new_array.append(i)
    print(new_array)
    return ''.join(new_array)


def remove_from_list(array, username):
    '''takes an array of username and a username to remove from it. Removes it and returns a string with slashes separating
    the remaining usernames, or an empty string if nothing remains.'''
    print(array)
    print(username)
    array.remove(username)
    if len(array) > 1:
        string = "/".join(array)
    elif array:
        string = array[0]
    else:
        string = ''
    return string

def social_distancing(string):
#Takes a string, replaces potentially dangerous characters with their HTML codes. Returns cleaned string.
    bad_guys = {"<": "&lt;", ">":"&gt;", '''"''':"&quot;", ";":"&#59;", ":":"&#58;", "=":"&#61;", 
    "[":"&#91;", "]":"&#93;", "/":"&#47;", "S":"&#83;", "s":"&#115;", "d":"&#100;", "D":"&#68;",
    "”":"&#148;", "“":"&#147;", """'""":"&#39;", "-":"&#45;"}
    #S/s are for Select and D/d are for Drop. A little overkill maybe but also i don't trust jonothan
    clean_string = "".join([bad_guys[i] if i in bad_guys else i for i in string])
    return clean_string

def seasoned_hash_brown(password, salt):
#Takes a password and a salt, concatenates the strings before hashing them. returns hashed password+salt.
    return sha256((password+salt).encode()).hexdigest()

def hashed_pass(password):
    '''Takes a password, generates a 32 character long salt for it, hashes the password with the salt,
    returns the hashed password and the salt used.'''
    chrs = """1234567890QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm"""
    salt = ""
    for i in range(32):
        salt += chrs[random.randint(0, len(chrs)-1)]
    password = seasoned_hash_brown(password, salt)
    return password, salt

def check_password(password, salt, hashed_password):
    '''Takes a password, salt, and hashed password. Checks if the password is correct by comparing the hashed password to
    the password and salt after hashing. Returns True if they match, False otherwise.'''
    if seasoned_hash_brown(password, salt) == hashed_password:
        return True
    return False



@app.route('/')
@login_check
def index():
#Home page. Gets fresh posts for the user. returns home page with posts.
    posts = get_posts(session)
    posts.reverse()
    return render_template('home.html', posts=posts, user_id=session["account"])


@app.route('/sign_up', methods=["GET", "POST"])
def sign_up():
    '''Sign up page. If get request is received, simply returns the sign up page template. If a post request is received,
gets form data from the request, checks if all inputs have been filled, checks if the username is already in use, checks
if username is long enough. If submitted info passes all of those, adds information as a new account to accounts database
and redirects the user to the login page with a message confirming that they have signed up. Otherwise, returns the sign up
page template based on what the user did wrong.'''
    if request.method == "POST":
        email = social_distancing(request.form.get("email"))
        username = social_distancing(request.form.get("username"))
        password = social_distancing(request.form.get("password"))
        query = text(f"SELECT * FROM ACCOUNTS WHERE username = '{username}';")
        if email and username and password and not_spaces(username) and not_spaces(password):
            result = connection.execute(query).fetchone()
            if not result and len(username)>1:
                password, salt = hashed_pass(password)
                query = text(f"INSERT INTO ACCOUNTS (username, password, email, salt) values(:username, :password, :email, :salt);")
                connection.execute(query, [{"username": username, "password":password, "email":email, "salt":salt}])
                connection.commit()
                return render_template("login.html", error="Successfully registered!")
            else:
                return render_template("sign_up.html", error="That username is unavaliable.")
        else:
            return render_template("sign_up.html", error="Please fill all fields.") 
    return render_template("sign_up.html")



@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = social_distancing(request.form.get("username"))
        password = social_distancing(request.form.get("password"))
        if username and password:
            query = text(f"SELECT * FROM ACCOUNTS WHERE username = '{username}';")
            result = connection.execute(query).fetchone()
            if result:
                account = get_account(username)
                if check_password(password, account.get_salt(), account.get_password()):
                    session["account"] = account.get_username()
                    return redirect('/')
            return render_template("login.html", error="Incorrect username or password.")
        else:
            return render_template("login.html", error="Please fill in all fields.")      

    return render_template("login.html")



@app.route('/chats', methods=["GET", "POST"])
@login_check
def chats():
    chat_list = get_account(session["account"]).get_chats()
    follower_list = get_account(session["account"]).get_followers()
    if request.method == "GET": 
        if chat_list:
            return render_template("chats.html", chat_list=chat_list, follower_list=follower_list)
        else:
            return render_template("chats.html", follower_list=follower_list)
            
    elif request.method == "POST":
        user = social_distancing(request.form.get("chat_with"))
        query = text(f"SELECT * FROM ACCOUNTS WHERE username='{user}';")
        result = connection.execute(query).fetchone()
        if result:
            user = get_account(user)
            if not user.is_blocked(get_account(session["account"])) and user.get_username() != session["account"]:
                users = sort_names([session['account'], user.get_username()])
                query = text(f"SELECT * FROM chats WHERE users='{users}';")
                result = connection.execute(query).fetchone()
                if not result:
                    chat_name = f"{session['account']}, {user.get_username()}"
                    query = text(f"INSERT INTO CHATS (users, chat_name) values(:users, :chat_name);")
                    connection.execute(query, [{"users": users, "chat_name":chat_name}])
                    connection.commit()
                    query = text(f"SELECT * FROM chats WHERE users='{users}';")
                    chat_id = Chat(connection.execute(query).fetchone()).get_chat_id()
                else:
                    result = Chat(result)
                    chat_id = result.get_chat_id()
                    chat_name = result.get_name()
                return redirect(url_for("chat", chat_id=chat_id, chat_name=chat_name))
            else:
                return render_template("chats.html", chat_list=chat_list, follower_list=follower_list, error="This user has blocked you.")
        else:
            return render_template("chats.html", chat_list=chat_list, follower_list=follower_list, error="This user doesn't exist.")




        

@app.route('/chat/<chat_id>', methods=["GET"])
@login_check
def chat(chat_id):
    no_chat = False
    try:
        chat_obj = get_chat(chat_id)
    except TypeError:
        no_chat = True
    messages = chat_obj.get_messages()
    message_count = chat_obj.message_count()
    chat_name = chat_obj.get_name()
    blocked_list = get_account(session["account"]).get_blocked()
    if request.method == 'GET' and chat_obj.in_chat(get_account(session["account"])) and not no_chat:
        content = request.args.get('content')
        if content and not_spaces(content):
            content = social_distancing(content)
            query = text(f"INSERT INTO MESSAGES (content, sender, chat_id, type) values(:content, :sender, :chat_id, :type);")
            connection.execute(query, [{"content": content, "sender": session["account"], "chat_id":chat_id, "type":"normal"}])
            connection.commit()
            return redirect(f'/refresh/chat/{chat_id}')
        if messages:
            last_message = messages[-1]
        else:
            last_message = Message(["", "", "", "", ""])
        return render_template("chat.html", chat_name = chat_name, message_list=messages, last_message=last_message,chat_id=chat_id, blocked_list=blocked_list, session=session, message_count=message_count, members=chat_obj.get_members())
    return redirect('/chats')
        

@app.route("/change_name", methods=["GET"])
@login_check
def name_change():
    name = social_distancing(request.args.get("name"))
    chat_id = request.args.get("chat_id")
    if name and not_spaces(name):
        query = text(f"UPDATE chats SET chat_name = '{name}' WHERE chat_id = '{chat_id}';")
        connection.execute(query)
        connection.commit()
    else:
        flash("Please enter a new name for the chat.")
    return redirect(f"/refresh/chat/{chat_id}")


@app.route("/add_member", methods=["GET"])
@login_check
def add_member():
    username = social_distancing(request.args.get("new_username"))
    chat_id = request.args.get("chat_id")
    print(f"AAAAAAAAAAAAAAAAAAA {chat_id}")
    chat_obj = get_chat(chat_id)
    query = text(f"SELECT * FROM ACCOUNTS WHERE username='{username}';")
    result = connection.execute(query).fetchone()
    if result:
        account = get_account(username)
        if not account.is_blocked(get_account(session["account"])) and not chat_obj.in_chat(account):
            string = sort_names(chat_obj.get_members())
            string += f"/{username}"
            print(string)
            query = text(f"UPDATE chats SET users = '{string}' WHERE chat_id = '{chat_id}';")
            print(query)
            connection.execute(query)
            connection.commit()
    else:
        flash("This user doesn't exist or has blocked you.")
    return redirect(f"/refresh/chat/{chat_id}")
        
        
@app.route('/leave_chat', methods=["GET"])
@login_check
def leave_chat():
    chat = get_chat(request.args.get("chat_id"))
    new_string = remove_from_list(chat.get_members(), session["account"])
    query = text(f"UPDATE chats SET users='{new_string}' WHERE chat_id = '{chat.get_chat_id()}';")
    connection.execute(query)
    connection.commit()
    return redirect("/chats")


@app.route("/new_msg_check", methods=["POST"])
def new_msg_check():
    msg_count = int(request.form.get("msg_count"))
    chat_id = int(request.form.get("chat_id"))
    chat_obj = get_chat(chat_id)
    if chat_obj.message_count() != msg_count:
        print("this bit is working")
        message = {"answer":'refresh'}
        return jsonify(message)
    message = {"answer":'all good'}
    return jsonify(message)







@app.route("/make_post", methods=["GET", "POST"])
@login_check
def make_post():
    if request.method == "GET":
        return render_template("make_post.html")
    elif request.method == "POST":
        t_content = social_distancing(request.form.get('t_content'))
        t_content = convert_breaks(list(t_content))
        if t_content and not_spaces(t_content):
            query = text(f"INSERT INTO POSTS (poster, content, dislikes, likes) values(:poster, :content, :dislikes, :likes);")
            connection.execute(query, [{"poster": session["account"], "content": t_content, "dislikes":0, "likes":0}])
            connection.commit()
            return redirect('/')
        return render_template("make_post.html")
            
@app.route('/logout')
def logout():
    session["account"] = ''
    return redirect('/login')




@app.route('/profile/<username>', methods=["GET"])
@login_check
def profile(username):
    username = social_distancing(username)
    account = get_account(username)
    posts = account.get_posted()
    print(posts)
    return render_template("profile.html", username = username, posts=posts, 
        is_follower=account.is_follower(get_account(session["account"])), is_blocked=get_account(session["account"]).is_blocked(account), session=session, 
        follower_count=len(account.get_followers()), user_id=session["account"])




@app.route('/profile_connections', methods=["POST"])
def profile_connections():
    action = request.form.get('action')
    recipient = request.form.get('recipient')
    self_user = get_account(session["account"])
    if 'block' in action:
        username = self_user.get_username()
        results = get_account(session["account"]).get_blocked()
        noun = 'blocked'
        if 'un' not in action:
            string = "/".join(results)+f"/{recipient}"
        else:
            string = remove_from_list(results, recipient)
    elif 'follow' in action:
        username = recipient
        account = get_account(recipient)
        results = account.get_followers()
        noun = 'followers'
        if 'un' not in action:
            string = "/".join(results)+f"/{self_user.get_username()}"
        else:
            string = remove_from_list(results, self_user.get_username())
    query = text(f"UPDATE Accounts SET {noun} = '{string}' WHERE username = '{username}';")
    print(f"query: {query}")
    connection.execute(query)
    connection.commit()

    return redirect(f'/profile/{recipient}')


@app.route("/interactions", methods=["POST"])
def thing_interactions():
    action = request.form.get('action')
    sign = request.form.get('sign')
    value = request.form.get('value')
    thing_id = request.form.get('thing_id')
    table = request.form.get('table')
    username = session["account"]
    results = get_interactions(thing_id, action, table)
    if sign == "1":
        print("true")
        string = "/".join(results)+f"/{username}"
        print(string)
    elif sign == "-1":
        string = remove_from_list(results, username)
    query = text(f"UPDATE {table} SET {action} = '{string}' WHERE {table[:-1]}_id = '{thing_id}';")
    connection.execute(query)
    connection.commit()
    return "all good"
    

@app.route("/post/<post_id>")
@login_check
def post(post_id):
    post = get_posts(session, post_id=post_id)
    comments = get_comments(post_id)
    return render_template("post.html", user_id=session["account"], post_id=post_id, post=post, comments=comments)




@app.route("/comment", methods=["POST"])
@login_check
def comment():
    content = social_distancing(request.form.get("content"))
    content = convert_breaks(list(content))
    post_id = request.form.get("post_id")
    root_comment = request.form.get("root_comment")
    if content:
        query = text(f"INSERT INTO COMMENTS (post_id, poster, content, likes, dislikes, root_comment) values(:post_id, :poster, :content, :likes, :dislikes, :root_comment);")
        connection.execute(query, [{"post_id": post_id, "poster": session["account"], "content": content, "dislikes":'', "likes":'', "root_comment": root_comment}])
        connection.commit()
    return redirect(f'/refresh/post/{post_id}')



@app.route("/explore", methods=["GET", "POST"])
@login_check
def explore():
    if request.method == 'GET':
        return render_template("explore.html", users=[], posts=[])
    elif request.method == 'POST':
        term = social_distancing(request.form.get("term"))
        print(term)
        if term and not_spaces(term):
            posts = search_posts(term, session)
            users = search_users(term, session)
            message = ''
        else:
            posts=[]
            users=[]
        if not posts and not users:
            message = "There doesn't seem to be anything here..."
        return render_template("explore.html", users=users, posts=posts, user_id=session["account"], message=message)


@app.route('/refresh/<page>/<thing_id>')
def refresh_chat(page, thing_id):
    return redirect(f"/{page}/{thing_id}")
    
    




if __name__ == "__main__":
    app.run(debug=True)
