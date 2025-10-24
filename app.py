from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from flask_cors import CORS # For handling Cross-Origin Resource Sharing
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
import os
from dotenv import load_dotenv
import uuid
import json
from datetime import datetime
from decimal import Decimal, InvalidOperation
load_dotenv() 

app = Flask(__name__)
CORS(app) # Enable CORS for frontend to access backend

# --- Configuration ---
# It's best practice to load sensitive data like database credentials from environment variables.
# This avoids hardcoding them in your source code.
DB_USER = os.environ.get('DB_USER', 'root')
DB_PASSWORD = os.environ.get('DB_PASSWORD') # Load password from environment variable
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_PORT = os.environ.get('DB_PORT', '3306')
DB_NAME = os.environ.get('DB_NAME', 'art_gallery_db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}' # Ensure PyMySQL is installed
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'your_secret_key_here') # Use environment variable for production

# --- Mail Configuration (for password reset) ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') # Your email address
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') # Your email app password
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

# --- File Upload Configuration ---
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB max upload size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = 'uploads' # Folder to store uploaded artwork images
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
mail = Mail(app)

# --- Flask-Login Configuration ---
login_manager = LoginManager()
login_manager.init_app(app)

# If an unauthenticated user tries to access a protected page,
# Flask-Login would normally redirect. Since this is an API, we'll return a 401 error.
@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({'message': 'Authentication required. Please log in.'}), 401

# Serializer for generating password reset tokens
ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# --- Database Models (using SQLAlchemy) --- # type: ignore
# The User model needs to inherit from UserMixin for Flask-Login to work
class User(db.Model, UserMixin): # type: ignore
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # The password_hash length is set to 512 to accommodate modern, long hashing algorithms (e.g., scrypt).
    # A shorter length (like 128) can cause silent truncation of the hash, leading to login failures.
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='buyer') # 'buyer', 'artist', 'admin'
    artworks = db.relationship('Artwork', backref='artist', lazy=True, cascade="all, delete-orphan") # Relationship for artists
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    orders = db.relationship('Order', backref='customer', lazy=True, cascade="all, delete-orphan")
    reviews = db.relationship('Review', backref='reviewer', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role
        }

class Artwork(db.Model): # type: ignore
    __tablename__ = 'artworks'
    id = db.Column(db.Integer, primary_key=True)
    artist_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False) # type: ignore
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Numeric(10, 2), nullable=False) # Use Numeric for precision with currency
    category = db.Column(db.String(50), nullable=False)
    image_path = db.Column(db.String(255), nullable=False) # Path to the image file
    upload_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    reviews = db.relationship('Review', backref='artwork_reviewed', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'artist_id': self.artist_id,
            # Access the back-referenced 'artist' object and convert it to a dict
            'artist': self.artist.to_dict() if self.artist else None,
            'title': self.title,
            'description': self.description,
            'price': float(self.price), # Convert Decimal to float for JSON serialization
            'category': self.category,
            'image_url': f'/uploads/{self.image_path}', # Construct full URL for the frontend
            'upload_date': self.upload_date.isoformat()
        }

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    order_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    total_amount = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending') # e.g., pending, completed, shipped
    items = db.relationship('OrderItem', backref='order', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'order_date': self.order_date.isoformat(),
            'total_amount': float(self.total_amount),
            'status': self.status,
            # --- Robustness Check: Filter out items where the artwork has been deleted ---
            # This prevents a 500 error if a purchased artwork is later removed from the gallery.
            'items': [item.to_dict() for item in self.items if item.artwork_item]
        }

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    artwork_id = db.Column(db.Integer, db.ForeignKey('artworks.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    price_at_purchase = db.Column(db.Numeric(10, 2), nullable=False)
    # Relationship to get artwork details from an order item
    artwork_item = db.relationship('Artwork')

    def to_dict(self):
        return {
            'id': self.id,
            'quantity': self.quantity,
            'price_at_purchase': float(self.price_at_purchase),
            'artwork': self.artwork_item.to_dict() if self.artwork_item else None
        }

class CartItem(db.Model):
    __tablename__ = 'cart_items'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    artwork_id = db.Column(db.Integer, db.ForeignKey('artworks.id', ondelete='SET NULL'), nullable=True)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    date_added = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Relationships
    artwork = db.relationship('Artwork')
    user = db.relationship('User', backref=db.backref('cart_items', lazy=True, cascade="all, delete-orphan"))

    def to_dict(self):
        return {
            'id': self.id,
            'quantity': self.quantity,
            'artwork': self.artwork.to_dict() if self.artwork else None
        }

class Review(db.Model):
    __tablename__ = 'reviews'
    id = db.Column(db.Integer, primary_key=True)
    artwork_id = db.Column(db.Integer, db.ForeignKey('artworks.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=True) # Rating from 1 to 5, now optional
    comment = db.Column(db.Text, nullable=True)
    review_date = db.Column(db.DateTime, default=db.func.current_timestamp())

    def to_dict(self):
        return {
            'id': self.id,
            'artwork_id': self.artwork_id,
            'user': self.reviewer.to_dict() if self.reviewer else None,
            'rating': self.rating,
            'comment': self.comment,
            'review_date': self.review_date.isoformat()
        }


# --- API Routes ---

# --- Flask-Login User Loader ---
# This function is used by Flask-Login to reload the user object from the user ID stored in the session.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Helper function for file validation ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Serve the main HTML file
@app.route('/')
def index():
    return render_template('art.html')

# User Registration
@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Request body must be JSON'}), 400

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'buyer').lower() # Default to 'buyer' and ensure lowercase

    # --- Enhanced Input Validation ---
    if not all([username, email, password]):
        return jsonify({'message': 'Missing required fields'}), 400

    if len(password) < 6:
        return jsonify({'message': 'Password must be at least 6 characters long.'}), 400

    # Validate role before hitting the database for better performance
    if role not in ['buyer', 'artist', 'admin']:
        return jsonify({'message': 'Invalid role specified'}), 400

    # --- Check for existing user ---
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already registered'}), 409
    
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username is already taken'}), 409

    # --- Create and save new user ---
    new_user = User(username=username, email=email, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    
    try:
        db.session.commit() # The user is saved and gets an ID from the database.
        db.session.refresh(new_user) # Ensure the user object has the ID from the database
    except Exception as e:
        db.session.rollback()
        print(f"Database error during registration: {e}") # For server-side logging
        return jsonify({'message': 'An internal error occurred. Please try again later.'}), 500

    # --- Automatically log in the user using Flask-Login's session management ---
    login_user(new_user)
    return jsonify({'message': 'User registered successfully', 'user': new_user.to_dict()}), 201

# User Login
@app.route('/api/login', methods=['POST'])
def handle_login(): # FIX: Renamed function to avoid conflict with flask_login.login_user
    data = request.get_json() # type: ignore

    email = data.get('email')
    password = data.get('password')

    # --- Enhanced Validation ---
    # Ensure data exists and contains the required fields before proceeding.
    if not data or not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        # Create a server-side session for the user
        login_user(user)
        return jsonify({'message': 'Login successful', 'user': user.to_dict()}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'You have been successfully logged out.'}), 200

# --- Password Reset Endpoints ---

# Step 1: User requests a password reset link
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()

    # --- Configuration Check: Prevent 500 error if mail is not set up ---
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        print("WARNING: Mail server is not configured. Cannot send password reset email.")
        return jsonify({'message': 'The password reset service is temporarily unavailable. Please contact support.'}), 503

    email = data.get('email')
    if not email:
        return jsonify({'message': 'Email is required.'}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        # Generate a time-sensitive token (expires in 1 hour)
        token = ts.dumps(user.email, salt='password-reset-salt')

        # This should be your frontend URL
        reset_url = f"http://127.0.0.1:5000/?reset_token={token}#reset-password"

        try:
            # Create and send the email
            msg = Message("Password Reset Request for ArtGallery", recipients=[user.email])
            msg.body = f"Hello {user.username},\n\nPlease click the following link to reset your password: {reset_url}\n\nIf you did not request this, please ignore this email.\n\nThanks,\nThe ArtGallery Team"
            mail.send(msg)
        except Exception as e:
            print(f"Mail sending error: {e}")
            return jsonify({'message': 'Could not send reset email. Please contact support.'}), 500

    # Always return a generic success message to prevent email enumeration
    return jsonify({'message': 'If an account with that email exists, a password reset link has been sent.'}), 200

# Step 2: User submits the new password with the token
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('password')

    if not token or not new_password:
        return jsonify({'message': 'Token and new password are required.'}), 400

    try:
        # Validate the token and get the email (expires after 3600 seconds = 1 hour)
        email = ts.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        return jsonify({'message': 'The password reset link has expired.'}), 400
    except BadTimeSignature:
        return jsonify({'message': 'The password reset link is invalid.'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Invalid user.'}), 404

    # Update the user's password
    user.set_password(new_password)
    db.session.commit()

    return jsonify({'message': 'Your password has been reset successfully! You can now log in.'}), 200

# --- User Profile Endpoints ---

@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    # With Flask-Login, the logged-in user is available via `current_user`
    if not current_user.is_authenticated:
        return jsonify({'message': 'User not found.'}), 404
    return jsonify(current_user.to_dict()), 200

@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    # FIX: Use the `current_user` object from Flask-Login instead of the old JWT function.
    user = current_user
    data = request.get_json() # type: ignore

    if not data:
        return jsonify({'message': 'Request body must be JSON.'}), 400

    # Handle username update
    new_username = data.get('username', '').strip()
    if new_username and new_username != user.username:
        # Check if the new username is already taken by another user
        if User.query.filter(User.username == new_username, User.id != user.id).first():
            return jsonify({'message': 'This username is already taken.'}), 409
        user.username = new_username
        db.session.commit()
        return jsonify({'message': 'Profile updated successfully.', 'user': user.to_dict()}), 200

    return jsonify({'message': 'No changes detected.'}), 200

@app.route('/api/profile/change-password', methods=['POST'])
@login_required
def change_password():
    user = current_user
    data = request.get_json() # type: ignore

    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')

    if not current_password or not new_password:
        return jsonify({'message': 'Both current and new passwords are required.'}), 400

    # Verify the current password
    if not user.check_password(current_password):
        return jsonify({'message': 'Your current password is incorrect.'}), 403

    # Set the new password
    user.set_password(new_password)
    db.session.commit()

    return jsonify({'message': 'Password changed successfully.'}), 200


# Get all artworks
@app.route('/api/artworks', methods=['GET'])
def get_artworks():
    search_term = request.args.get('search')
    query = Artwork.query.options(db.joinedload(Artwork.artist)) # Eager load artist data

    if search_term:
        # Case-insensitive search across multiple fields
        search_filter = or_(
            Artwork.title.ilike(f'%{search_term}%'),
            Artwork.description.ilike(f'%{search_term}%'),
            Artwork.category.ilike(f'%{search_term}%'),
            User.username.ilike(f'%{search_term}%') # Search by artist name
        )
        query = query.join(User, Artwork.artist_id == User.id).filter(search_filter)

    artworks = query.order_by(Artwork.upload_date.desc()).all()
    return jsonify([artwork.to_dict() for artwork in artworks])

# Get single artwork by ID
@app.route('/api/artworks/<int:artwork_id>', methods=['GET'])
def get_artwork(artwork_id):
    artwork = Artwork.query.get_or_404(artwork_id)
    return jsonify(artwork.to_dict()), 200

# --- Review Endpoints ---

# Get all reviews for a specific artwork
@app.route('/api/artworks/<int:artwork_id>/reviews', methods=['GET'])
def get_artwork_reviews(artwork_id):
    # Ensure the artwork exists
    Artwork.query.get_or_404(artwork_id)
    # Use joinedload to prevent the N+1 query problem. This fetches all reviews and their
    # corresponding user (reviewer) data in a single, efficient database query.
    reviews = Review.query.filter_by(artwork_id=artwork_id).options(db.joinedload(Review.reviewer)).order_by(Review.review_date.desc()).all()
    return jsonify([review.to_dict() for review in reviews]), 200

# Post a new review for an artwork
@app.route('/api/artworks/<int:artwork_id>/reviews', methods=['POST'])
@login_required
def post_artwork_review(artwork_id):
    current_user_id = current_user.id
    artwork = Artwork.query.get_or_404(artwork_id) # type: ignore
    data = request.get_json()

    if not data:
        return jsonify({'message': 'Invalid request data.'}), 400

    rating = data.get('rating')
    comment = data.get('comment', '').strip()

    # A review must have at least a comment or a rating.
    if not comment and (rating is None or rating == 0):
        return jsonify({'message': 'A review must contain a rating or a comment.'}), 400

    # Validate rating only if it's provided and not 0.
    if rating is not None and rating != 0 and (not isinstance(rating, int) or not (1 <= rating <= 5)):
        return jsonify({'message': 'If provided, rating must be an integer between 1 and 5.'}), 400

    # Prevent an artist from reviewing their own work
    if artwork.artist_id == current_user_id:
        return jsonify({'message': 'You cannot review your own artwork.'}), 403

    # Check if the user has already reviewed this artwork
    if Review.query.filter_by(user_id=current_user_id, artwork_id=artwork_id).first():
        return jsonify({'message': 'You have already reviewed this artwork.'}), 409

    try:
        # If rating is 0 or None, save it as NULL in the database.
        new_review = Review(
            artwork_id=artwork_id, user_id=current_user_id, 
            rating=rating if rating and rating > 0 else None, 
            comment=comment)
        db.session.add(new_review)
        db.session.commit()
        return jsonify({'message': 'Review submitted successfully!', 'review': new_review.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error during review submission: {e}")
        return jsonify({'message': 'An internal error occurred while submitting the review.'}), 500

# Update a review
@app.route('/api/reviews/<int:review_id>', methods=['PUT'])
@login_required
def update_review(review_id):
    review = Review.query.get_or_404(review_id)

    # Security Check: Ensure the user owns the review
    if review.user_id != current_user.id:
        return jsonify({'message': 'You do not have permission to edit this review.'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'message': 'Invalid request data.'}), 400

    rating = data.get('rating')
    comment = data.get('comment', '').strip()

    # A review must have at least a comment or a rating.
    if not comment and (rating is None or rating == 0):
        return jsonify({'message': 'A review must contain a rating or a comment.'}), 400

    # Validate rating only if it's provided and not 0.
    if rating is not None and rating != 0 and (not isinstance(rating, int) or not (1 <= rating <= 5)):
        return jsonify({'message': 'If provided, rating must be an integer between 1 and 5.'}), 400

    review.rating = rating if rating and rating > 0 else None
    review.comment = comment
    db.session.commit()

    return jsonify({'message': 'Review updated successfully!', 'review': review.to_dict()}), 200

# Delete a review
@app.route('/api/reviews/<int:review_id>', methods=['DELETE'])
@login_required
def delete_review(review_id):
    review = Review.query.get_or_404(review_id)

    # Security Check: Allow deletion if user is the owner OR an admin
    if review.user_id != current_user.id and current_user.role != 'admin':
        return jsonify({'message': 'You do not have permission to delete this review.'}), 403

    try:
        db.session.delete(review)
        db.session.commit()
        return jsonify({'message': 'Review deleted successfully.'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error during review deletion: {e}")
        return jsonify({'message': 'An internal error occurred while deleting the review.'}), 500

# Get artworks for the currently logged-in artist
@app.route('/api/my-artworks', methods=['GET'])
@login_required
def get_my_artworks():
    current_user_id = current_user.id
    artist = current_user
    if not artist or artist.role != 'artist':
        # This case should ideally not be hit if frontend logic is correct, but it's good practice
        return jsonify({'message': 'You must be an artist to view this page.'}), 403

    # Fetch artworks uploaded by the current artist, ordered by most recent
    artworks = Artwork.query.filter_by(artist_id=current_user_id).options(db.joinedload(Artwork.artist)).order_by(Artwork.upload_date.desc()).all()
    return jsonify([artwork.to_dict() for artwork in artworks]), 200

# --- Order History Endpoint ---
@app.route('/api/orders', methods=['GET'])
@login_required
def get_order_history():
    user_id = current_user.id
    # Fetch all orders for the user, most recent first
    orders = Order.query.filter_by(user_id=user_id).options(db.joinedload(Order.items).joinedload(OrderItem.artwork_item).joinedload(Artwork.artist)).order_by(Order.order_date.desc()).all()
    return jsonify([order.to_dict() for order in orders]), 200

# --- Artist Sales Dashboard Endpoint ---
@app.route('/api/artist/sales', methods=['GET'])
@login_required
def get_artist_sales():
    artist_id = current_user.id
    artist = current_user
    if not artist or artist.role != 'artist':
        return jsonify({'message': 'Access denied. Only artists can view sales data.'}), 403

    # Find all order items that contain artworks by the current artist
    sales = db.session.query(OrderItem).join(Artwork).filter(Artwork.artist_id == artist_id).join(Order).order_by(Order.order_date.desc()).all()

    sales_data = []
    for sale in sales:
        # --- Robustness Check: Prevent 500 error if a sold artwork was deleted ---
        # If the artwork associated with the sale no longer exists, skip it.
        if not sale.artwork_item:
            continue
        sales_data.append({
            'order_id': sale.order.id,
            'order_date': sale.order.order_date.isoformat(),
            'artwork_title': sale.artwork_item.title,
            'artwork_image_url': f'/uploads/{sale.artwork_item.image_path}',
            'quantity': sale.quantity,
            'sale_price': float(sale.price_at_purchase),
            'customer': sale.order.customer.to_dict()
        })

    return jsonify(sales_data), 200

# --- Shopping Cart Endpoints ---

# Get items in the user's cart
@app.route('/api/cart', methods=['GET'])
@login_required
def get_cart():
    user_id = current_user.id
    cart_items = CartItem.query.filter_by(user_id=user_id).options(db.joinedload(CartItem.artwork).joinedload(Artwork.artist)).order_by(CartItem.date_added.desc()).all()
    
    # --- Robustness Check: Filter out items where the artwork has been deleted ---
    valid_cart_items = [item for item in cart_items if item.artwork]

    # Calculate total in the same loop to avoid extra DB hits from the frontend
    total = sum(item.artwork.price * item.quantity for item in valid_cart_items)
    
    return jsonify({
        # Return only the items that are still valid
        'items': [item.to_dict() for item in valid_cart_items],
        'total': float(total)
    }), 200

# Add an item to the cart
@app.route('/api/cart/add', methods=['POST'])
@login_required
def add_to_cart():
    user_id = current_user.id
    data = request.get_json()
    artwork_id = data.get('artwork_id')

    if not artwork_id:
        return jsonify({'message': 'Artwork ID is required.'}), 400

    artwork = Artwork.query.get_or_404(artwork_id)

    # Prevent artist from adding their own work to the cart
    if artwork.artist_id == user_id:
        return jsonify({'message': 'You cannot purchase your own artwork.'}), 403

    # Check if the item is already in the cart
    cart_item = CartItem.query.filter_by(user_id=user_id, artwork_id=artwork_id).first()
    if cart_item:
        # For simplicity, we'll just confirm it's already there. You could also increase quantity here.
        return jsonify({'message': 'This item is already in your cart.'}), 409
    else:
        new_item = CartItem(user_id=user_id, artwork_id=artwork_id, quantity=1)
        db.session.add(new_item)
        db.session.commit()
        return jsonify({'message': 'Artwork added to cart.', 'item': new_item.to_dict()}), 201

# Remove an item from the cart
@app.route('/api/cart/item/<int:item_id>', methods=['DELETE'])
@login_required
def remove_from_cart(item_id):
    user_id = current_user.id
    cart_item = CartItem.query.get_or_404(item_id)

    if cart_item.user_id != user_id:
        return jsonify({'message': 'Unauthorized.'}), 403

    db.session.delete(cart_item)
    db.session.commit()
    return jsonify({'message': 'Item removed from cart.'}), 200

# Checkout: Create an order from cart items
@app.route('/api/cart/checkout', methods=['POST'])
@login_required
def checkout():
    user_id = current_user.id
    cart_items = CartItem.query.filter_by(user_id=user_id).all()

    if not cart_items:
        return jsonify({'message': 'Your cart is empty.'}), 400

    try:
        # --- Robustness Check: Ensure all artworks in cart still exist ---
        for item in cart_items:
            if not item.artwork: # type: ignore
                # This item's artwork was deleted. Abort checkout.
                return jsonify({'message': f'An item in your cart is no longer available. Please remove it and try again.'}), 409

        total_amount = sum(item.artwork.price * item.quantity for item in cart_items) # type: ignore

        # Create a new order
        new_order = Order(user_id=user_id, total_amount=total_amount, status='pending')
        db.session.add(new_order)

        # Create order items and clear the cart
        for item in cart_items:
            order_item = OrderItem(
                order=new_order,
                artwork_id=item.artwork_id, # type: ignore
                quantity=item.quantity,
                price_at_purchase=item.artwork.price # type: ignore
            )
            db.session.add(order_item)
            db.session.delete(item) # Remove from cart

        db.session.commit()

        # --- Send Order Confirmation Email ---
        try:
            customer_email = current_user.email
            customer_name = current_user.username
            order_id = new_order.id
            order_total = new_order.total_amount
            
            # Render the HTML email template
            html_body = render_template(
                'email/order_confirmation.html', 
                user=current_user, 
                order=new_order,
                now=datetime.utcnow() # Pass current time for the copyright year
            )
            # It's good practice to also provide a plain-text version for email clients that don't render HTML.
            text_body = f"Thank you for your order, {customer_name}! Your order #{order_id} for ${order_total:.2f} has been confirmed."
            
            msg = Message("Your ArtGallery Order Confirmation", recipients=[customer_email])
            msg.body = text_body
            msg.html = html_body
            mail.send(msg)
        except Exception as e:
            # Log the error, but don't fail the entire transaction if the email fails.
            # The order is already successfully processed.
            print(f"CRITICAL: Order #{new_order.id} succeeded but failed to send confirmation email. Error: {e}")

        return jsonify({'message': 'Checkout successful! Your order has been placed.', 'order_id': new_order.id}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error during checkout: {e}")
        return jsonify({'message': 'An internal error occurred during checkout.'}), 500

# Upload artwork (requires authentication and artist role)
@app.route('/api/artworks', methods=['POST'])
@login_required
def upload_artwork():
    artist = current_user
    if not artist.is_authenticated:
        # A valid token points to a user that no longer exists.
        return jsonify({'message': 'Authenticated user not found in database.'}), 404

    if artist.role != 'artist':
        return jsonify({'message': 'Only artists can upload artwork'}), 403

    # --- Input Validation ---
    # Check for presence of required form fields first
    if 'title' not in request.form or 'price' not in request.form or 'category' not in request.form:
        return jsonify({'message': 'Missing required fields: title, price, or category.'}), 400
    if 'image' not in request.files:
        return jsonify({'message': 'An image file is required.'}), 400

    # Get data from the form
    title = request.form.get('title', '')
    description = request.form.get('description', '') # Default to empty string
    price_str = request.form.get('price')
    category = request.form.get('category', '')
    image_file = request.files.get('image')

    # Validate the content of the fields
    if not title.strip():
        return jsonify({'message': 'Title is required.'}), 400
    if not category.strip():
        return jsonify({'message': 'Category is required.'}), 400
    if not image_file or image_file.filename == '':
        return jsonify({'message': 'An image file is required.'}), 400

    # --- Enhanced Validation: Price and File Type ---
    try:
        price_decimal = Decimal(price_str)
        if price_decimal <= 0:
            return jsonify({'message': 'Price must be a positive number.'}), 400
    except (InvalidOperation, TypeError):
        return jsonify({'message': 'Invalid price format. Please enter a valid number.'}), 400

    if not allowed_file(image_file.filename):
        return jsonify({'message': f"Invalid file type. Allowed types are: {', '.join(app.config['ALLOWED_EXTENSIONS'])}"}), 400

    try:
        # --- Generate a unique filename and save the file ---
        original_filename = secure_filename(image_file.filename)
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        unique_id = str(uuid.uuid4().hex)[:6]
        image_filename = f"{timestamp}_{unique_id}_{original_filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
        image_file.save(filepath)

        # --- Create and save the artwork record ---
        new_artwork = Artwork(
            artist_id=artist.id,
            title=title,
            description=description,
            price=price_decimal,
            category=category,
            image_path=image_filename
        )
        db.session.add(new_artwork)
        db.session.commit()
        # Refresh the object to load all database-defaults (like upload_date) and relationships
        db.session.refresh(new_artwork)

        return jsonify({'message': 'Artwork uploaded successfully!', 'artwork': new_artwork.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error during artwork upload: {e}") # For server-side logging
        return jsonify({'message': 'An internal error occurred during file processing.'}), 500

# Update an artwork (requires authentication and ownership)
@app.route('/api/artworks/<int:artwork_id>', methods=['PUT'])
@login_required
def update_artwork(artwork_id):
    current_user_id = current_user.id
    # --- Security Check: Ensure the user owns the artwork ---
    artwork = Artwork.query.filter_by(id=artwork_id, artist_id=current_user_id).first_or_404( # type: ignore
        description='Artwork not found or you do not have permission to edit it.')

    data = request.get_json()
    if not data:
        return jsonify({'message': 'Request body must be JSON.'}), 400

    # --- Validate and update fields ---
    # Use .get() to avoid errors if a field is not provided, falling back to the existing value.
    artwork.title = data.get('title', artwork.title).strip()
    artwork.description = data.get('description', artwork.description).strip()
    artwork.category = data.get('category', artwork.category).strip()

    if not artwork.title or not artwork.category:
        return jsonify({'message': 'Title and Category are required fields.'}), 400

    # Validate price separately due to its numeric type
    price_str = data.get('price')
    if price_str is not None:
        try:
            price_decimal = Decimal(str(price_str))
            if price_decimal <= 0:
                return jsonify({'message': 'Price must be a positive number.'}), 400
            artwork.price = price_decimal
        except (InvalidOperation, TypeError):
            return jsonify({'message': 'Invalid price format.'}), 400

    try:
        db.session.commit()
        # Refresh the object to ensure the returned data is fully up-to-date
        db.session.refresh(artwork)
        return jsonify({'message': 'Artwork updated successfully.', 'artwork': artwork.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error during artwork update: {e}")
        return jsonify({'message': 'An internal error occurred while updating.'}), 500

# Delete an artwork (requires authentication and ownership)
@app.route('/api/artworks/<int:artwork_id>', methods=['DELETE'])
@login_required
def delete_artwork(artwork_id):
    current_user_id = current_user.id
    artwork = Artwork.query.get_or_404(artwork_id)

    # --- Security Check: Allow deletion if user is the owner OR an admin ---
    if artwork.artist_id != current_user_id and current_user.role != 'admin': # type: ignore
        return jsonify({'message': 'Unauthorized. You can only delete your own artworks.'}), 403

    try:
        # --- Pre-emptive Cleanup: Remove this artwork from all user carts ---
        # This prevents 500 errors if a user tries to view a cart with a deleted item.
        CartItem.query.filter_by(artwork_id=artwork_id).delete()

        # --- Delete the image file from the server ---
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], artwork.image_path)
        if os.path.exists(image_path):
            os.remove(image_path)

        # --- Delete the artwork record from the database ---
        db.session.delete(artwork)
        db.session.commit()

        return jsonify({'message': 'Artwork deleted successfully.'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error during artwork deletion: {e}")
        return jsonify({'message': 'An internal error occurred while deleting the artwork.'}), 500

# Serve uploaded images
@app.route('/uploads/<filename>')
def serve_upload(filename):
    # This route is crucial for the frontend to be able to display uploaded images.
    # It securely serves files from your UPLOAD_FOLDER.
    return send_from_directory(os.path.abspath(app.config['UPLOAD_FOLDER']), filename)

# Admin routes (conceptual)
@app.route('/api/admin/users', methods=['GET'])
@login_required
def get_all_users():
    # --- Security Check: Ensure the user is an admin ---
    if not current_user.is_authenticated or current_user.role != 'admin':
        return jsonify({'message': 'Unauthorized: Admin access required.'}), 403
        
    users = User.query.order_by(User.id).all()
    return jsonify([user.to_dict() for user in users]), 200

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    """
    Renders a server-side admin dashboard page.
    This page is only accessible to users with the 'admin' role.
    """
    if not current_user.is_authenticated or current_user.role != 'admin':
        # You can render a custom error page or redirect
        return render_template('error.html', message="You do not have permission to access this page."), 403

    # Fetch data for the dashboard
    users = User.query.order_by(User.username).all()
    orders = Order.query.options(
        db.joinedload(Order.customer), 
        db.joinedload(Order.items).joinedload(OrderItem.artwork_item)
    ).order_by(Order.order_date.desc()).all()

    return render_template('admin_dashboard.html', users=users, orders=orders)

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    # --- Security Check: Ensure the current user is an admin ---
    if not current_user.is_authenticated or current_user.role != 'admin':
        return jsonify({'message': 'Unauthorized: Admin access required.'}), 403

    # --- Prevent admin from deleting themselves ---
    if current_user.id == user_id:
        return jsonify({'message': 'Admins cannot delete their own account.'}), 400

    user_to_delete = User.query.get_or_404(user_id)

    try:
        # The database schema is set up with `ON DELETE CASCADE` for artworks, orders,
        # reviews, and cart items. Deleting the user will automatically clean up
        # all their associated records, which is efficient but powerful.
        db.session.delete(user_to_delete)
        db.session.commit()
        return jsonify({'message': f'User "{user_to_delete.username}" and all their associated data have been deleted.'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error during user deletion: {e}")
        return jsonify({'message': 'An internal error occurred while deleting the user.'}), 500

@app.route('/api/admin/orders/<int:order_id>/status', methods=['PUT'])
@login_required
def update_order_status(order_id):
    # --- Security Check: Ensure the current user is an admin ---
    if not current_user.is_authenticated or current_user.role != 'admin':
        return jsonify({'message': 'Unauthorized: Admin access required.'}), 403

    order = Order.query.get_or_404(order_id)
    data = request.get_json()
    new_status = data.get('status')

    if not new_status:
        return jsonify({'message': 'New status is required.'}), 400
    
    # Validate the new status against a list of allowed statuses
    allowed_statuses = ['pending', 'completed', 'shipped', 'cancelled']
    if new_status not in allowed_statuses:
        return jsonify({'message': f'Invalid status. Must be one of: {", ".join(allowed_statuses)}'}), 400

    order.status = new_status
    db.session.commit()

    return jsonify({'message': f'Order #{order.id} status updated to {new_status}.', 'order': order.to_dict()}), 200

# Initial database setup (run once)
@app.cli.command('initdb')
def initdb_command():
    """Initializes the database."""
    db.create_all()
    print('Initialized the database.')

@app.cli.command('testdb')
def testdb_command():
    """Tests the database connection."""
    try:
        db.session.execute(db.text('SELECT 1'))
        print('✅ Database connection successful.')
    except Exception as e:
        print('❌ Database connection failed. Please check the steps below.')
        print(f"Error: {e}")

if __name__ == '__main__':

    # To run: flask run
    # Before running, ensure you have MySQL server running and database created.
    # Then, run `flask initdb` to create tables.
    app.run(debug=True) # debug=True for development, False for production