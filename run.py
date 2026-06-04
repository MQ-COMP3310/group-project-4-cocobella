import os
import sys
import re
import tempfile
from importlib import reload
from flask import Flask, render_template, redirect, request, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Needed for encoding to utf8
reload(sys)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "some_secret")
data = []

# Task 9 - Feature 1: Rate limiting
# Security principle: defence in depth for availability (CIA - Availability).
# Mitigates DoS identified in Task 3 (OWASP A04 Insecure Design).
# Per-IP limits prevent one client exhausting server resources (RL-01).
# Snapshot
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    headers_enabled=True,
)


@app.errorhandler(429)
def rate_limit_exceeded(error):
    # RL-04: fail closed with generic message — no internal config leaked.
    return render_template("rate_limited.html", page_title="Too Many Requests"), 429


# Flat-file storage is used to match the existing project structure.
USERS_FILE = "data/-users.txt"
SCORES_FILE = "data/-score-history.txt"

# Bcrypt hashes passwords, Flask-Login manages sessions, and CSRF protects forms.
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

csrf = CSRFProtect(app)

# Usernames are filtered because they are used in file names.
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{2,20}$")

# User model used by Flask-Login.
class User(UserMixin):
    def __init__(self, username, password_hash=None, role="user", cur_score=0, high_score=0, raw_password=None):
        self.id = username
        self.username = username
        self.role = role
        self.cur_score = int(cur_score)
        self.high_score = int(high_score)

        if raw_password is not None:
            self.password_hash = bcrypt.generate_password_hash(raw_password).decode("utf-8")
        else:
            self.password_hash = password_hash

    def verify_password(self, password):
        if not self.password_hash:
            return False
        return bcrypt.check_password_hash(self.password_hash, password)

    def get_id(self):
        return self.username

# Returns True only when the username matches the allowed pattern.
def valid_username(username):
    return bool(username and USERNAME_RE.fullmatch(username))

# Looks up one user record for login and session loading.
def get_user_data_from_file(username_to_find):
    try:
        with open(USERS_FILE, "r") as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                try:
                    username, password_hash, role, cur_score, high_score = line.split(":", 4)

                    if username == username_to_find:
                        return User(username, password_hash, role, cur_score, high_score)

                except ValueError:
                    app.logger.warning("Skipped malformed user record.")

    except FileNotFoundError:
        return None

    return None

# Loads all registered users for admin display.
def get_all_users_data():
    users = []

    try:
        with open(USERS_FILE, "r") as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                try:
                    username, password_hash, role, cur_score, high_score = line.split(":", 4)
                    users.append(User(username, password_hash, role, cur_score, high_score))

                except ValueError:
                    app.logger.warning("Skipped malformed user record.")

    except FileNotFoundError:
        return []

    return users

# New users are saved with hashed passwords, not plaintext passwords.
def write_user_to_file(user):
    try:
        with open(USERS_FILE, "a") as f:
            f.write(f"{user.username}:{user.password_hash}:{user.role}:{user.cur_score}:{user.high_score}\n")
        return True

    except IOError:
        app.logger.error("Could not write user data.")
        return False

# Updates scores using a temporary file to reduce file corruption risk.
def update_user_score_in_file(username_to_update, new_cur_score=None, new_high_score=None):
    users = []
    user_found = False

    try:
        with open(USERS_FILE, "r") as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                try:
                    username, password_hash, role, cur_score, high_score = line.split(":", 4)

                    if username == username_to_update:
                        user_found = True

                        if new_cur_score is not None:
                            cur_score = str(new_cur_score)

                        if new_high_score is not None:
                            high_score = str(new_high_score)

                    users.append(f"{username}:{password_hash}:{role}:{cur_score}:{high_score}\n")

                except ValueError:
                    app.logger.warning("Skipped malformed user record.")

        if not user_found:
            return False

        fd, temp_path = tempfile.mkstemp(dir="data", text=True)

        with os.fdopen(fd, "w") as temp_file:
            temp_file.writelines(users)

        os.replace(temp_path, USERS_FILE)
        return True

    except FileNotFoundError:
        return False

    except IOError:
        app.logger.error("Could not update user data.")
        return False

# Allows admins to update a registered user's role and high score.
def update_user_admin(username_to_update, new_role, new_high_score):
    users = []
    user_found = False

    try:
        with open(USERS_FILE, "r") as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                try:
                    username, password_hash, role, cur_score, high_score = line.split(":", 4)

                    if username == username_to_update:
                        user_found = True
                        role = new_role
                        high_score = str(new_high_score)

                    users.append(f"{username}:{password_hash}:{role}:{cur_score}:{high_score}\n")

                except ValueError:
                    app.logger.warning("Skipped malformed user record.")

        if not user_found:
            return False

        fd, temp_path = tempfile.mkstemp(dir="data", text=True)

        with os.fdopen(fd, "w") as temp_file:
            temp_file.writelines(users)

        os.replace(temp_path, USERS_FILE)
        return True

    except (FileNotFoundError, IOError):
        return False

# Removes a registered user account from the user file.
def delete_user_from_file(username_to_delete):
    users = []
    user_found = False

    try:
        with open(USERS_FILE, "r") as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                try:
                    username, password_hash, role, cur_score, high_score = line.split(":", 4)

                    if username == username_to_delete:
                        user_found = True
                        continue

                    users.append(f"{username}:{password_hash}:{role}:{cur_score}:{high_score}\n")

                except ValueError:
                    app.logger.warning("Skipped malformed user record.")

        if not user_found:
            return False

        fd, temp_path = tempfile.mkstemp(dir="data", text=True)

        with os.fdopen(fd, "w") as temp_file:
            temp_file.writelines(users)

        os.replace(temp_path, USERS_FILE)
        return True

    except (FileNotFoundError, IOError):
        return False

# Saves the score only if it is higher than the user's current high score.
def save_high_score_for_user(username, score):
    user = get_user_data_from_file(username)

    if not user:
        return False

    if int(score) > user.high_score:
        return update_user_score_in_file(username, new_high_score=score)

    return True

# Stores previous scores so users can view their score history.
def add_score_history(username, score):
    try:
        with open(SCORES_FILE, "a") as f:
            f.write(f"{username}:{score}\n")
        return True
    except IOError:
        app.logger.error("Could not save score history.")
        return False

# Reads all stored scores for one username.
def get_score_history(username_to_find):
    scores = []

    try:
        with open(SCORES_FILE, "r") as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                try:
                    username, score = line.split(":", 1)

                    if username == username_to_find:
                        scores.append(int(score))

                except ValueError:
                    app.logger.warning("Skipped malformed score record.")

    except FileNotFoundError:
        return []

    return scores

# Removes score history for registered or anonymous users.
def delete_score_history(username_to_delete):
    remaining_scores = []

    try:
        with open(SCORES_FILE, "r") as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                try:
                    username, score = line.split(":", 1)

                    if username != username_to_delete:
                        remaining_scores.append(f"{username}:{score}\n")

                except ValueError:
                    app.logger.warning("Skipped malformed score record.")

        directory = os.path.dirname(SCORES_FILE) or "."
        fd, temp_path = tempfile.mkstemp(dir=directory, text=True)

        with os.fdopen(fd, "w") as temp_file:
            temp_file.writelines(remaining_scores)

        os.replace(temp_path, SCORES_FILE)
        return True

    except (FileNotFoundError, IOError, OSError):
        return False

# Removes matching scores from the public highscore board.
def delete_public_highscores(username_to_delete):
    remaining_lines = []

    try:
        with open("data/-highscores.txt", "r") as f:
            lines = f.read().splitlines()

        for i in range(0, len(lines), 2):
            try:
                username = lines[i]
                score = lines[i + 1]

                if username != username_to_delete:
                    remaining_lines.append(username + "\n")
                    remaining_lines.append(score + "\n")

            except IndexError:
                pass

        fd, temp_path = tempfile.mkstemp(dir="data", text=True)

        with os.fdopen(fd, "w") as temp_file:
            temp_file.writelines(remaining_lines)

        os.replace(temp_path, "data/-highscores.txt")
        return True

    except (FileNotFoundError, IOError):
        return False

# Flask-Login uses this to reload the current user from the session.
@login_manager.user_loader
def load_user(user_id):
    return get_user_data_from_file(user_id)

# Rejects form submissions with missing or invalid CSRF tokens.
@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    return "CSRF validation failed.", 400

# Makes the CSRF token available to all templates.
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

# Appends game data to the existing text files.
def write_to_file(filename, data):
    with open(filename, "a+") as file:
        file.writelines(data)


#This is where the riddles live
def riddle():
    riddles = []
    with open("data/-riddles.txt", "r") as e:
        lines = e.read().splitlines()
    for line in lines:
        riddles.append(line)
    return riddles


# This is where the answers for the riddles live
def riddle_answers():
    answers = []
    with open("data/-answers.txt", "r") as e:
        lines = e.read().splitlines()
    for line in lines:
        answers.append(line)
    return answers


# Clear functions for wrong answers and score
def clear_guesses(username):
    with open("data/user-" + username + "-guesses.txt", "w"):
        return

def clear_score(username):
    with open("data/user-" + username + "-score.txt", "w"):
        return


# Wrong answer handling
def store_all_attempts(username):
    attempts = []
    with open("data/user-" + username + "-guesses.txt", "r") as incorrect_attempts:
        attempts = incorrect_attempts.readlines()
    return attempts

def num_of_attempts(username):
    attempts = store_all_attempts(username)
    return len(attempts)

def attempts_remaining(username):
    remaining_attempts = 3 - num_of_attempts(username)
    return remaining_attempts


# Score gets lower the more attempts used
def add_to_score(username):
    round_score = 4 - num_of_attempts(username)
    return round_score

#Adds all the scores from all riddles to make final score
def end_score(username):
    with open("data/user-" + username + "-score.txt", "r") as numbers_file:
        total = 0
        for line in numbers_file:
            try:
                total += int(line)
            except ValueError:
                pass
    return total

#Add final score to highscore list after the last riddle
def final_score(username):
    score = str(end_score(username))

    if username != "" and score != "":
        with open("data/-highscores.txt", "a") as file:
            file.writelines(username + "\n")
            file.writelines(score + "\n")

        add_score_history(username, int(score))

        if current_user.is_authenticated and current_user.username == username:
            save_high_score_for_user(username, int(score))
            current_user.high_score = max(current_user.high_score, int(score))
    else:
        return

#Used to retrieve scores from highscore file for use on highscore page
def get_scores():
    scores_by_user = {}

    try:
        with open("data/-highscores.txt", "r") as file:
            lines = file.read().splitlines()

        for i in range(0, len(lines), 2):
            try:
                username = lines[i]
                score = int(lines[i + 1])

                if username not in scores_by_user or score > scores_by_user[username]:
                    scores_by_user[username] = score

            except (IndexError, ValueError):
                pass

    except FileNotFoundError:
        pass

    for user in get_all_users_data():
        if user.high_score > 0:
            if user.username not in scores_by_user or user.high_score > scores_by_user[user.username]:
                scores_by_user[user.username] = user.high_score

    usernames_and_scores = sorted(scores_by_user.items(), key=lambda x: x[1], reverse=True)

    return usernames_and_scores[:10]

# Shows admins both registered users and anonymous score owners.
def get_admin_content_rows():
    content = {}

    for user in get_all_users_data():
        content[user.username] = {
            "username": user.username,
            "role": user.role,
            "high_score": user.high_score,
            "registered": True
        }

    try:
        with open("data/-highscores.txt", "r") as file:
            lines = file.read().splitlines()

        for i in range(0, len(lines), 2):
            try:
                username = lines[i]
                score = int(lines[i + 1])

                if username not in content:
                    content[username] = {
                        "username": username,
                        "role": "unregistered",
                        "high_score": score,
                        "registered": False
                    }
                elif score > content[username]["high_score"]:
                    content[username]["high_score"] = score

            except (IndexError, ValueError):
                pass

    except FileNotFoundError:
        pass

    try:
        with open(SCORES_FILE, "r") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    username, score = line.split(":", 1)
                    score = int(score)

                    if username not in content:
                        content[username] = {
                            "username": username,
                            "role": "unregistered",
                            "high_score": score,
                            "registered": False
                        }
                    elif score > content[username]["high_score"]:
                        content[username]["high_score"] = score

                except ValueError:
                    pass

    except FileNotFoundError:
        pass

    return sorted(content.values(), key=lambda x: x["username"])

# Registers new users after validating username and password input.
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not valid_username(username):
            flash("Username must be 2-20 characters and only use letters, numbers, underscores or hyphens.")
            return render_template("register.html")

        if get_user_data_from_file(username):
            flash("Username is already taken.")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.")
            return render_template("register.html")

        user = User(
            username=username,
            raw_password=password,
            role="user",
            cur_score=0,
            high_score=0
        )

        if write_user_to_file(user):
            flash("Account created. Please log in.")
            return redirect(url_for("login"))

        flash("Account could not be created.")

    return render_template("register.html")

# Authenticates users using the stored bcrypt password hash.
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        user = get_user_data_from_file(username)

        if user and user.verify_password(password):
            login_user(user)
            flash("Logged in successfully.")
            return redirect(url_for("index"))

        flash("Login failed. Check your username and password.")

    return render_template("login.html")

# Ends the user's authenticated session.
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

# Logged-in users can view their high score and previous scores.
@app.route("/profile")
@login_required
def profile():
    scores = get_score_history(current_user.username)
    return render_template("profile.html", scores=scores)

# Public score sharing page that can be viewed without logging in.
@app.route("/share/<username>")
def share_score(username):
    username = username.strip().lower()

    if not valid_username(username):
        return "Invalid username.", 400

    user = get_user_data_from_file(username)

    if not user:
        return "User not found.", 404

    scores = get_score_history(username)
    return render_template("share_score.html", user=user, scores=scores)

# Admin only route for editing users and deleting score content.
@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    if current_user.role != "admin":
        return "You do not have permission.", 403

    if request.method == "POST":
        action = request.form.get("action")
        username = request.form.get("username", "").strip().lower()

        if username == current_user.username and action == "delete":
            flash("You cannot delete your own admin account.")
            return redirect(url_for("admin"))

        if action == "update":
            role = request.form.get("role", "user").strip().lower()
            high_score = request.form.get("high_score", "0").strip()

            if role not in ["user", "admin"]:
                flash("Invalid role.")
                return redirect(url_for("admin"))

            try:
                high_score = int(high_score)
            except ValueError:
                flash("Invalid score.")
                return redirect(url_for("admin"))

            if not get_user_data_from_file(username):
                flash("Only registered users can have role or profile score updated.")
                return redirect(url_for("admin"))

            if update_user_admin(username, role, high_score):
                flash("User updated.")
            else:
                flash("User could not be updated.")

        elif action == "delete":
            deleted_user = delete_user_from_file(username)
            deleted_scores = delete_score_history(username)
            deleted_public_scores = delete_public_highscores(username)

            if deleted_user or deleted_scores or deleted_public_scores:
                flash("User content deleted.")
            else:
                flash("User content could not be deleted.")

        return redirect(url_for("admin"))

    users = get_admin_content_rows()
    return render_template("admin.html", users=users)

# HOMEPAGE
# Logged-in users play under their account name; anonymous users enter a safe username.
@app.route('/', methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def index():
    if current_user.is_authenticated:
        if request.method == "POST":
            return redirect(url_for('user', username=current_user.username))

        return render_template("index.html", page_title="Home", username=current_user.username)

    if request.method == "POST":
        username = request.form["username"].strip().lower()

        if username == "":
            return render_template("index.html", page_title="Home", username=username)

        if not valid_username(username):
            flash("Username must be 2-20 characters and only use letters, numbers, underscores or hyphens.")
            return render_template("index.html", page_title="Home", username=username)

        return redirect(url_for('user', username=username))

    return render_template("index.html", page_title="Home")


# USER WELCOME PAGE
@app.route('/<username>', methods=["GET", "POST"])
@limiter.limit("20 per minute")
def user(username):

    username = username.strip().lower()

    if not valid_username(username):
        return "Invalid username.", 400

    # Prevent logged-in users from accessing another user's game URL.
    if current_user.is_authenticated and username != current_user.username:
        return "You do not have permission.", 403

    # Create a User Specific File for Score Keeping etc.
    open("data/user-" + username + "-score.txt", 'a').close()
    clear_score(username)
    open("data/user-" + username + "-guesses.txt", 'a').close()
    clear_guesses(username)

    if request.method =="POST":
        return redirect(url_for('game', username=username))

    return render_template("welcome.html",
                            username=username)


# GAME PAGE
@app.route('/<username>/game', methods=["GET", "POST"])
@limiter.limit("60 per minute")
def game(username):

    username = username.strip().lower()

    if not valid_username(username):
        return "Invalid username.", 400

    # Prevent logged-in users from accessing another user's game URL.
    if current_user.is_authenticated and username != current_user.username:
        return "You do not have permission.", 403

    remaining_attempts = 3
    riddles = riddle()
    riddle_index = 0
    answers = riddle_answers()
    score = 0

    if request.method == "POST":

        riddle_index = int(request.form["riddle_index"])
        user_response = request.form["answer"].title()

        write_to_file("data/user-" + username + "-guesses.txt", user_response + "\n")

        # Compare the user's answer to the correct answer of the riddle
        if answers[riddle_index] == user_response:
            # Correct answer
            if riddle_index < 9:
                # If riddle number is less than 10 & answer is correct: add score, clear wrong answers file and go to next riddle
                write_to_file("data/user-" + username + "-score.txt", str(add_to_score(username)) + "\n")
                clear_guesses(username)
                riddle_index += 1
            else:
                # If right answer on LAST riddle: add score, submit score to highscore file and redirect to congrats page
                write_to_file("data/user-" + username + "-score.txt", str(add_to_score(username)) + "\n")
                final_score(username)
                return redirect(url_for('congrats', username=username, score=end_score(username)))

        else:
            # Incorrect answer
            if attempts_remaining(username) > 0:
                # if answer was wrong and more than 0 attempts remaining, reload current riddle
                riddle_index = riddle_index
            else:
                # If all attempts are used up, redirect to Gameover page
                return redirect(url_for('gameover', username=username))

    return render_template("game.html",
                            username=username, riddle_index=riddle_index, riddles=riddles,
                             attempts=store_all_attempts(username), remaining_attempts=attempts_remaining(username), score=end_score(username))


# GAMEOVER PAGE
@app.route('/<username>/gameover', methods=["GET", "POST"])
@limiter.limit("20 per minute")
def gameover(username):

    username = username.strip().lower()

    if not valid_username(username):
        return "Invalid username.", 400
    
    # Prevent logged-in users from accessing another user's game URL.
    if current_user.is_authenticated and username != current_user.username:
        return "You do not have permission.", 403

    final_game_score = end_score(username)

    if final_game_score > 0:
        add_score_history(username, final_game_score)

    if current_user.is_authenticated and current_user.username == username:
        save_high_score_for_user(username, final_game_score)
        current_user.high_score = max(current_user.high_score, final_game_score)

    clear_guesses(username)
    clear_score(username)

    if request.method =="POST":

        return redirect(url_for('game', username=username))

    return render_template("gameover.html",
                            username=username)


# FINISH PAGE
@app.route('/<username>/congratulations', methods=["GET", "POST"])
@limiter.limit("20 per minute")
def congrats(username):

    username = username.strip().lower()

    if not valid_username(username):
        return "Invalid username.", 400
    
    # Prevent logged-in users from accessing another user's game URL.
    if current_user.is_authenticated and username != current_user.username:
        return "You do not have permission.", 403

    clear_guesses(username)

    if request.method =="POST":
        usernames_and_scores = get_scores()
        return redirect(url_for('highscores', usernames_and_scores=usernames_and_scores))

    return render_template("congratulations.html",
                            username=username, score=end_score(username))


# HIGHSCORE PAGE
@app.route('/highscores')
@limiter.limit("30 per minute")
def highscores():

    usernames_and_scores = get_scores()

    return render_template("highscores.html", page_title="Highscores", usernames_and_scores=usernames_and_scores)


if __name__ == '__main__':
    ip = "127.0.0.1"
    port = 8000
    app.run(host=ip,
            port=port,
            debug=False)
