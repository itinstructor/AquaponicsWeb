from flask import send_from_directory, render_template, request, redirect, url_for, flash, session, abort, jsonify, current_app, make_response
from . import blog_bp
from database import db
from sqlalchemy.orm import selectinload
from .models import BlogPost, Photo, Video, User, BlogImage, LoginAttempt
from .auth import validate_password, get_client_ip, log_login_attempt
from .utils import save_uploaded_image
from datetime import datetime, timezone
from functools import wraps
import logging
import os
import secrets
import time
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash

MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10MB
UPLOAD_FOLDER = os.path.join(os.path.dirname(
    os.path.dirname(__file__)), 'photos')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# ADD: Create logger at the top of the file
logger = logging.getLogger(__name__)

PHOTOS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'photos')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

os.makedirs(PHOTOS_DIR, exist_ok=True)


def login_required(f):
    """Decorator to require login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('blog_bp.login'))
        return f(*args, **kwargs)
    return decorated_function


def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@blog_bp.route('/blog-home')
def index():
    """Main homepage with latest Sarah T blog posts."""
    user = User.query.filter(User.username.ilike('sarah t')).first()
    posts = []
    if user:
        posts = BlogPost.query.filter_by(author_id=user.id, published=True).order_by(BlogPost.created_at.desc()).limit(2).all()
    # Provide stream_url and timestamp for camera if needed
    stream_url = '/static/stream.jpg'  # Adjust as needed
    timestamp = int(datetime.now(timezone.utc).timestamp())
    return render_template('index.html', latest_sarah_posts=posts, stream_url=stream_url, timestamp=timestamp)


@blog_bp.route('/blog')
def blog():
    """Blog listing page - only show published posts."""
    user = User.query.get(session.get('user_id')
                          ) if 'user_id' in session else None
    # Optimization: Use selectinload to avoid N+1 queries for author usernames in the template.
    # This fetches all authors for the posts in a single extra query instead of one per post.
    posts = BlogPost.query.options(selectinload(BlogPost.author))\
        .filter_by(published=True)\
        .order_by(BlogPost.created_at.desc())\
        .all()
    resp = make_response(render_template(
        'blog_blog.html', posts=posts, user=user))
    # Prevent browser/proxy caching so previews reflect latest content
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


@blog_bp.route('/post/<slug>')
def view_post(slug):
    user = User.query.get(session.get('user_id')
                          ) if 'user_id' in session else None
    # Optimization: Eagerly load the author to avoid a separate query.
    post = BlogPost.query.options(selectinload(BlogPost.author))\
        .filter_by(slug=slug)\
        .first_or_404()

    # Only allow viewing published posts (unless you're the author)
    if not post.published and (session.get('user_id') != post.author_id):
        flash('This post is not published yet.', 'warning')
        return redirect(url_for('blog_bp.blog'))

    # Increment view count
    post.view_count += 1
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating view count: {e}")

    return render_template('blog_view_post.html', post=post, user=user)


# Removed old nasa_bp route decorator
@blog_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')
        captcha_user = request.form.get('captcha', '').strip()
        captcha_answer = request.form.get('captcha_answer', '').strip()

        # Validate CAPTCHA
        if not captcha_user or not captcha_answer:
            flash('Please complete the security check.', 'danger')
            return render_template('blog_register.html')

        try:
            if int(captcha_user) != int(captcha_answer):
                flash('Incorrect answer to security question.', 'danger')
                return render_template('blog_register.html')
        except ValueError:
            flash('Invalid security answer.', 'danger')
            return render_template('blog_register.html')

        # Validate input
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('blog_register.html')

        if password != password_confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('blog_register.html')

        # Password strength check
        if len(password) < 16:
            flash('Password must be at least 12 characters long.', 'danger')
            return render_template('blog_register.html')

        complexity_count = 0
        if any(c.isupper() for c in password):
            complexity_count += 1
        if any(c.islower() for c in password):
            complexity_count += 1
        if any(c.isdigit() for c in password):
            complexity_count += 1
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            complexity_count += 1

        if complexity_count < 3:
            flash(
                'Password must contain at least 3 of: uppercase, lowercase, number, symbol.', 'danger')
            return render_template('blog_register.html')

        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return render_template('blog_register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('blog_register.html')

        # Create user (unapproved by default)
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            is_approved=False  # Add this line
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            flash(
                'Registration successful! Your account is pending admin approval.', 'success')
            return redirect(url_for('blog_bp.login'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Registration error: {e}")
            flash('Registration failed. Please try again.', 'danger')
            return render_template('blog_register.html')
    return render_template('blog_register.html')


@blog_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        client_ip = get_client_ip()

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('blog_login.html')

        user = User.query.filter_by(username=username).first()

        if not user:
            log_login_attempt(username, False)
            flash('Invalid username or password.', 'danger')
            return render_template('blog_login.html')

        # Check if user is approved
        if not user.is_approved:
            log_login_attempt(username, False)
            flash('Your account is pending admin approval.', 'warning')
            return render_template('blog_login.html')

        if user.is_locked():
            flash(
                f'Account is locked due to too many failed attempts. Try again after {user.locked_until.strftime("%I:%M %p")}', 'danger')
            return render_template('blog_login.html')

        if user.check_password(password):
            user.reset_failed_logins()
            db.session.commit()
            session['user_id'] = user.id
            session['username'] = user.username
            log_login_attempt(username, True)
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('blog_bp.dashboard'))
        else:
            user.increment_failed_login()
            db.session.commit()
            log_login_attempt(username, False)
            remaining = 10 - user.failed_login_attempts
            if remaining > 0:
                flash(
                    f'Invalid password. {remaining} attempts remaining before lockout.', 'danger')
            else:
                flash(
                    'Account locked for 30 minutes due to too many failed attempts.', 'danger')
    return render_template('blog_login.html')


@blog_bp.route('/logout')
def logout():
    """Log out current user."""
    session.clear()
    flash('You have been logged out.', 'info')
    # After logout, return to the blog listing so the application context remains correct
    return redirect(url_for('blog_bp.blog'))


@blog_bp.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    posts = BlogPost.query.filter_by(
        author_id=session['user_id']
    ).order_by(BlogPost.created_at.desc()).all()
    return render_template('blog_dashboard.html', posts=posts, user=user)


@blog_bp.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    """Create a new blog post."""

    try:
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()
            excerpt = request.form.get('excerpt', '').strip()
            published = request.form.get('published') == 'on'

            logging.info(
                f"New post attempt: title={title}, published={published}")

            if not title or not content:
                flash('Title and content are required.', 'danger')
                return render_template('blog_edit_post.html', post=None)

            # Generate unique slug
            from slugify import slugify
            base_slug = slugify(title)
            slug = base_slug
            counter = 1
            while BlogPost.query.filter_by(slug=slug).first():
                slug = f"{base_slug}-{counter}"
                counter += 1

            logging.info(f"Generated slug: {slug}")

            post = BlogPost(
                title=title,
                slug=slug,
                content=content,
                excerpt=excerpt[:500] if excerpt else content[:200] + '...',
                published=published,
                author_id=session['user_id']
            )
            db.session.add(post)
            db.session.flush()  # Get post.id before handling images

            # Handle image uploads
            uploaded_files = request.files.getlist('images')
            for file in uploaded_files:
                if file and file.filename and allowed_file(file.filename):
                    try:
                        # Check file size
                        file.seek(0, os.SEEK_END)
                        file_size = file.tell()
                        file.seek(0)

                        if file_size > MAX_IMAGE_SIZE:
                            flash(
                                f'Image {file.filename} is too large (max 10MB)', 'warning')
                            continue

                        # Save image
                        filename, file_path, width, height, saved_size = save_uploaded_image(
                            file, UPLOAD_FOLDER
                        )

                        # Create database record
                        image = BlogImage(
                            filename=filename,
                            original_filename=file.filename,
                            file_path=file_path,
                            mime_type=file.content_type or 'image/jpeg',
                            file_size=saved_size,
                            width=width,
                            height=height,
                            post_id=post.id,
                            uploaded_by=session['user_id']
                        )
                        db.session.add(image)
                        logging.info(f"Image {filename} added to post")
                    except Exception as e:
                        logging.exception(
                            f"Failed to upload image {file.filename}")
                        flash(
                            f'Failed to upload {file.filename}', 'warning')

            db.session.commit()
            logging.info(f"Post created successfully with ID: {post.id}")
            flash('Post created successfully!', 'success')
            return redirect(url_for('blog_bp.dashboard'))
        return render_template('blog_edit_post.html', post=None)

    except Exception as e:
        logging.exception("Error in new_post route")
        import traceback
        return f"<h1>New Post Error</h1><pre>{traceback.format_exc()}</pre>", 500


@blog_bp.route('/post/<slug>/edit', methods=['GET', 'POST'])
def edit_post(slug):
    if 'user_id' not in session:
        flash('Please log in to edit posts.', 'danger')
        return redirect(url_for('blog_bp.login'))

    user = User.query.get(session['user_id'])
    post = BlogPost.query.filter_by(slug=slug).first_or_404()

    # Check if user is the author
    if post.author_id != session['user_id']:
        flash('You can only edit your own posts.', 'danger')
        return redirect(url_for('blog_bp.dashboard'))

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        excerpt = request.form.get('excerpt', '')
        published = request.form.get('published') == 'on'

        post.title = title
        post.content = content
        # Security/Data Integrity: Store the raw excerpt. Stripping HTML should be done in the template.
        post.excerpt = excerpt
        post.published = published
        post.updated_at = datetime.utcnow()

        # Update slug if title changed
        from slugify import slugify
        new_slug = slugify(title)
        if new_slug != post.slug:
            # Check if new slug already exists
            existing = BlogPost.query.filter_by(slug=new_slug).first()
            if existing and existing.id != post.id:
                new_slug = f"{new_slug}-{post.id}"
            post.slug = new_slug

        try:
            db.session.commit()
            flash('Post updated successfully!', 'success')
            return redirect(url_for('blog_bp.view_post', slug=post.slug))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating post: {e}")
            flash('An error occurred while updating the post.', 'danger')

    return render_template('blog_edit_post.html', post=post, user=user)


@blog_bp.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    """Delete a blog post."""
    post = BlogPost.query.get_or_404(post_id)

    if post.author_id != session['user_id']:
        abort(403)

    try:
        db.session.delete(post)
        db.session.commit()
        flash('Post deleted successfully.', 'success')
    except Exception:
        logging.exception("Failed to delete post")
        db.session.rollback()
        flash('Failed to delete post.', 'danger')
    return redirect(url_for('blog_bp.dashboard'))


@blog_bp.route('/upload_image', methods=['POST'])
@login_required
def upload_image():
    """
    CKEditor Simple Upload Adapter endpoint.
    Expects multipart/form-data with file in field "upload" (CKEditor default).
    Returns JSON: { "url": "<path>" } on success, or HTTP 400/500 with JSON error.
    """
    try:
        file = request.files.get('upload') or request.files.get('file')
        if not file or file.filename == '':
            return jsonify({'error': {'message': 'No file uploaded'}}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': {'message': 'File type not allowed'}}), 400

        # ensure upload folder exists
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        original = secure_filename(file.filename)
        ext = original.rsplit('.', 1)[1].lower()
        filename = f"{secrets.token_urlsafe(12)}.{ext}"
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        # limit size if you want (optional)
        file.save(file_path)

        # optional: create DB record (BlogImage) if you keep image metadata
        try:
            img = BlogImage(
                filename=filename,
                original_filename=original,
                file_path=file_path,
                mime_type=file.mimetype or f'image/{ext}',
                file_size=os.path.getsize(file_path),
                width=None,
                height=None,
                post_id=None,
                uploaded_by=session.get('user_id')
            )
            db.session.add(img)
            db.session.commit()
        except Exception:
            # non-fatal: don't block upload if DB fails
            db.session.rollback()
            current_app.logger.exception(
                "Failed to write image metadata to DB")

        # return URL for CKEditor to insert
        url = url_for('static', filename=f'uploads/{filename}')
        return jsonify({'url': url}), 201

    except Exception as e:
        current_app.logger.exception("Image upload failed")
        return jsonify({'error': {'message': 'Upload failed'}}), 500


@blog_bp.route('/posts')
def all_posts():
    """Renders a page with a list of all published posts."""
    try:
        # Optimization: Use selectinload to prevent N+1 queries for author data in the template.
        posts = BlogPost.query.options(selectinload(BlogPost.author))\
            .filter_by(published=True)\
            .order_by(BlogPost.created_at.desc())\
            .all()

        return render_template('blog_all_posts.html', posts=posts, title="All Posts")
    except Exception as e:
        current_app.logger.error(f"Error fetching all posts: {e}")
        flash('Could not retrieve blog posts at this time.', 'danger')
        # Or some other appropriate page
        return redirect(url_for('blog_bp.dashboard'))


def get_current_user():
    """Get current logged-in user from session."""
    user_id = session.get('user_id')
    if user_id:
        try:
            return User.query.get(user_id)
        except Exception:
            return None
    return None


@blog_bp.route("/photos")
def photos():
    """Display photo gallery."""
    try:
        all_photos = Photo.query.order_by(Photo.sort_order.asc(), Photo.created_at.desc()).all()
        logger.info(f"Loaded {len(all_photos)} photos")
    except Exception as e:
        logger.exception(f"Could not load photos: {e}")
        all_photos = []
    
    user = get_current_user()
    
    return render_template("photos.html", photos=all_photos, user=user)


@blog_bp.route("/photos/<path:filename>")
def serve_photo(filename):
    """Serve photo files."""
    return send_from_directory(PHOTOS_DIR, filename)


@blog_bp.route("/photos/upload", methods=["GET", "POST"])
@login_required
def upload_photo():
    """Handle photo upload."""
    user = get_current_user()
    if not user:
        flash("Please log in to upload photos", "error")
        return redirect(url_for('blog_bp.login'))
    
    if request.method == "GET":
        return render_template("blog_upload_photo.html")
    
    if 'photo' not in request.files:
        flash("No file selected", "error")
        return redirect(url_for('blog_bp.photos'))
    
    file = request.files['photo']
    if file.filename == '':
        flash("No file selected", "error")
        return redirect(url_for('blog_bp.photos'))
    
    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(file.filename)
            base, ext = os.path.splitext(filename)
            filename = f"{base}_{int(time.time())}{ext}"
            
            filepath = os.path.join(PHOTOS_DIR, filename)
            file.save(filepath)
            
            caption = request.form.get('caption', '')
            description = request.form.get('description', '')
            
            photo = Photo(
                filename=filename,
                caption=caption,
                description=description,
                uploaded_by=user.id
            )
            db.session.add(photo)
            db.session.commit()
            
            logger.info(f"Photo uploaded: {filename}")
            flash("Photo uploaded successfully!", "success")
        except Exception as e:
            logger.exception(f"Photo upload failed: {e}")
            flash(f"Upload failed: {e}", "error")
    else:
        flash("Invalid file type. Allowed: PNG, JPG, JPEG, GIF, WEBP", "error")
    
    return redirect(url_for('blog_bp.photos'))


@blog_bp.route("/photos/delete/<int:photo_id>", methods=["POST"])
@login_required
def delete_photo(photo_id):
    """Delete a photo."""
    user = get_current_user()
    if not user:
        flash("Please log in", "error")
        return redirect(url_for('blog_bp.login'))
    
    try:
        photo = Photo.query.get_or_404(photo_id)
        filepath = os.path.join(PHOTOS_DIR, photo.filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        db.session.delete(photo)
        db.session.commit()
        flash("Photo deleted!", "success")
    except Exception as e:
        logger.exception(f"Delete failed: {e}")
        flash(f"Delete failed: {e}", "error")
    
    return redirect(url_for('blog_bp.photos'))


@blog_bp.route("/photos/edit/<int:photo_id>", methods=["GET", "POST"])
def edit_photo(photo_id):
    """Edit photo caption and description."""
    user = get_current_user()
    if not user:
        flash("Please log in to edit photos", "error")
        return redirect(url_for('blog_bp.login'))
    
    photo = Photo.query.get_or_404(photo_id)
    
    if request.method == "POST":
        try:
            photo.caption = request.form.get('caption', '')
            photo.description = request.form.get('description', '')
            db.session.commit()
            
            logger.info(f"Photo {photo_id} updated")
            flash("Photo updated!", "success")
            return redirect(url_for('blog_bp.photos'))
        except Exception as e:
            logger.exception(f"Photo update failed: {e}")
            flash(f"Update failed: {e}", "error")
    
    return render_template("edit_photo.html", photo=photo, user=user)  # FIX: Use correct template name


@blog_bp.route("/photos/reorder", methods=["POST"])
def reorder_photos():
    """Reorder photos via drag and drop."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    
    try:
        order = request.json.get('order', [])
        for index, photo_id in enumerate(order):
            photo = Photo.query.get(photo_id)
            if photo:
                photo.sort_order = index
        db.session.commit()
        logger.info(f"Photos reordered: {order}")
        return jsonify({"success": True})
    except Exception as e:
        logger.exception(f"Reorder failed: {e}")
        return jsonify({"error": str(e)}), 500


# ============================================================================
# VIDEO ROUTES - YouTube video management
# ============================================================================

@blog_bp.route('/videos')
def videos():
    """Display all videos."""
    try:
        all_videos = Video.query.order_by(Video.order.asc(), Video.created_at.desc()).all()
        user = get_current_user()
        return render_template('videos.html', videos=all_videos, user=user)
    except Exception as e:
        logger.exception(f"Error loading videos: {e}")
        flash('Could not load videos.', 'danger')
        return redirect(url_for('blog_bp.index'))


@blog_bp.route('/video/add', methods=['GET', 'POST'])
@login_required
def add_video():
    """Add a new video."""
    user = get_current_user()
    if not user:
        flash('Please log in to add videos.', 'danger')
        return redirect(url_for('blog_bp.login'))
    
    if request.method == 'POST':
        try:
            youtube_url = request.form.get('youtube_id', '').strip()
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            
            # Extract YouTube ID from URL if it's a full URL
            youtube_id = youtube_url
            if 'youtube.com/watch?v=' in youtube_url:
                youtube_id = youtube_url.split('v=')[1].split('&')[0]
            elif 'youtu.be/' in youtube_url:
                youtube_id = youtube_url.split('youtu.be/')[1].split('?')[0]
            
            if not youtube_id or not title:
                flash('YouTube ID/URL and title are required.', 'danger')
                return render_template('add_video.html')
            
            # Check for duplicates
            existing = Video.query.filter_by(youtube_id=youtube_id).first()
            if existing:
                flash('This video already exists.', 'warning')
                return render_template('add_video.html')
            
            # Get max order and add 1
            max_order = db.session.query(db.func.max(Video.order)).scalar() or 0
            
            video = Video(
                youtube_id=youtube_id,
                title=title,
                description=description,
                order=max_order + 1
            )
            db.session.add(video)
            db.session.commit()
            
            logger.info(f"Video added: {youtube_id}")
            flash('Video added successfully!', 'success')
            return redirect(url_for('blog_bp.videos'))
        except Exception as e:
            logger.exception(f"Error adding video: {e}")
            flash(f'Error adding video: {e}', 'danger')
            return render_template('add_video.html')
    
    return render_template('add_video.html')


@blog_bp.route('/video/<int:video_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_video(video_id):
    """Edit a video."""
    user = get_current_user()
    if not user:
        flash('Please log in to edit videos.', 'danger')
        return redirect(url_for('blog_bp.login'))
    
    video = Video.query.get_or_404(video_id)
    
    if request.method == 'POST':
        try:
            video.title = request.form.get('title', '').strip()
            video.description = request.form.get('description', '').strip()
            db.session.commit()
            
            logger.info(f"Video {video_id} updated")
            flash('Video updated!', 'success')
            return redirect(url_for('blog_bp.videos'))
        except Exception as e:
            logger.exception(f"Video update failed: {e}")
            db.session.rollback()
            flash(f'Update failed: {e}', 'danger')
    
    return render_template('edit_video.html', video=video, user=user)


@blog_bp.route('/video/<int:video_id>/delete', methods=['POST'])
@login_required
def delete_video(video_id):
    """Delete a video."""
    user = get_current_user()
    if not user:
        flash('Please log in', 'danger')
        return redirect(url_for('blog_bp.login'))
    
    try:
        video = Video.query.get_or_404(video_id)
        db.session.delete(video)
        db.session.commit()
        logger.info(f"Video {video_id} deleted")
        flash('Video deleted!', 'success')
    except Exception as e:
        logger.exception(f"Delete failed: {e}")
        db.session.rollback()
        flash(f'Delete failed: {e}', 'danger')
    
    return redirect(url_for('blog_bp.videos'))


@blog_bp.route('/videos/reorder', methods=['POST'])
@login_required
def reorder_videos():
    """Reorder videos via drag and drop."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    
    try:
        order = request.json.get('order', [])
        for index, video_id in enumerate(order):
            video = Video.query.get(video_id)
            if video:
                video.order = index
        db.session.commit()
        logger.info(f"Videos reordered: {order}")
        return jsonify({"success": True})
    except Exception as e:
        logger.exception(f"Reorder failed: {e}")
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@blog_bp.route('/admin')
@login_required
def admin():
    """Admin panel for managing users"""
    current_user = User.query.get(session['user_id'])
    if not current_user or not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('blog_bp.index'))

    # Optimization: Eagerly load posts for each user to get the post count
    # without triggering N+1 queries when calling `user.posts|length` in the template.
    all_users = User.query.options(
        selectinload(User.posts)
    ).order_by(User.created_at.desc()).all()

    return render_template('blog_admin.html', users=all_users, user=current_user)


@blog_bp.route('/admin/user/<int:user_id>/approve', methods=['POST'])
@login_required
def approve_user(user_id):
    """Approve a user"""
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('blog_bp.index'))

    target_user = User.query.get_or_404(user_id)
    target_user.is_approved = True
    db.session.commit()

    flash(f'User {target_user.username} has been approved.', 'success')
    return redirect(url_for('blog_bp.admin'))


@blog_bp.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
def toggle_admin(user_id):
    """Toggle admin status for a user"""
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('blog_bp.index'))

    target_user = User.query.get_or_404(user_id)

    # Prevent removing your own admin status
    if target_user.id == user.id:
        flash('You cannot change your own admin status.', 'warning')
        return redirect(url_for('blog_bp.admin'))

    target_user.is_admin = not target_user.is_admin
    db.session.commit()

    status = 'granted' if target_user.is_admin else 'revoked'
    flash(f'Admin privileges {status} for {target_user.username}.', 'success')
    return redirect(url_for('blog_bp.admin'))


@blog_bp.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    """Delete a user"""
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('blog_bp.index'))

    target_user = User.query.get_or_404(user_id)

    # Prevent deleting yourself
    if target_user.id == user.id:
        flash('You cannot delete your own account.', 'warning')
        return redirect(url_for('blog_bp.admin'))

    username = target_user.username
    db.session.delete(target_user)
    db.session.commit()

    flash(f'User {username} has been deleted.', 'success')
    return redirect(url_for('blog_bp.admin'))


@blog_bp.route('/admin/user/<int:user_id>/edit', methods=['POST'])
@login_required
def edit_user(user_id):
    """Edit user details"""
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('blog_bp.index'))

    target_user = User.query.get_or_404(user_id)

    # Get form data
    username = request.form.get('username')
    email = request.form.get('email')
    is_active = request.form.get('is_active') == 'on'
    is_admin = request.form.get('is_admin') == 'on'
    is_approved = request.form.get('is_approved') == 'on'

    # Prevent removing admin status from loringw
    if target_user.username == 'loringw' and not is_admin:
        flash('Cannot remove admin status from loringw.', 'warning')
        return redirect(url_for('blog_bp.admin'))

    # Check if username or email already exists (for other users)
    existing_username = User.query.filter(
        User.username == username, User.id != user_id).first()
    if existing_username:
        flash(f'Username "{username}" is already taken.', 'danger')
        return redirect(url_for('blog_bp.admin'))

    existing_email = User.query.filter(
        User.email == email, User.id != user_id).first()
    if existing_email:
        flash(f'Email "{email}" is already in use.', 'danger')
        return redirect(url_for('blog_bp.admin'))

    # Update user
    target_user.username = username
    target_user.email = email
    target_user.is_active = is_active
    target_user.is_admin = is_admin
    target_user.is_approved = is_approved

    try:
        db.session.commit()
        flash(f'User {username} has been updated.', 'success')
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating user: {e}")
        flash('An error occurred while updating the user.', 'danger')
    return redirect(url_for('blog_bp.admin'))


@blog_bp.route('/admin/user/<int:user_id>/reset_password', methods=['POST'])
@login_required
def reset_password(user_id):
    """Reset a user's password"""
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('blog_bp.index'))

    target_user = User.query.get_or_404(user_id)

    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    # Validate passwords
    if not new_password or not confirm_password:
        flash('Both password fields are required.', 'danger')
        return redirect(url_for('blog_bp.admin'))

    if new_password != confirm_password:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('blog_bp.admin'))

    # Password strength check
    if len(new_password) < 16:
        flash('Password must be at least 16 characters long.', 'danger')
        return redirect(url_for('blog_bp.admin'))

    complexity_count = 0
    if any(c.isupper() for c in new_password):
        complexity_count += 1
    if any(c.islower() for c in new_password):
        complexity_count += 1
    if any(c.isdigit() for c in new_password):
        complexity_count += 1
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in new_password):
        complexity_count += 1

    if complexity_count < 3:
        flash('Password must contain at least 3 of: uppercase, lowercase, number, symbol.', 'danger')
        return redirect(url_for('blog_bp.admin'))

    # Update password
    target_user.password_hash = generate_password_hash(new_password)
    target_user.failed_login_attempts = 0  # Reset failed login attempts
    target_user.locked_until = None  # Unlock account if locked

    try:
        db.session.commit()
        flash(
            f'Password reset successfully for {target_user.username}.', 'success')
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error resetting password: {e}")
        flash('An error occurred while resetting the password.', 'danger')
    return redirect(url_for('blog_bp.admin'))


@blog_bp.route('/admin/user/add', methods=['POST'])
@login_required
def add_user():
    """Add a new user from admin panel"""
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('blog_bp.index'))

    # Get form data
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    is_active = request.form.get('is_active') == 'on'
    is_admin = request.form.get('is_admin') == 'on'
    is_approved = request.form.get('is_approved') == 'on'

    # Validate input
    if not username or not email or not password:
        flash('Username, email, and password are required.', 'danger')
        return redirect(url_for('blog_bp.admin'))

    if password != confirm_password:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('blog_bp.admin'))

    # Password strength check
    if len(password) < 16:
        flash('Password must be at least 16 characters long.', 'danger')
        return redirect(url_for('blog_bp.admin'))

    complexity_count = 0
    if any(c.isupper() for c in password):
        complexity_count += 1
    if any(c.islower() for c in password):
        complexity_count += 1
    if any(c.isdigit() for c in password):
        complexity_count += 1
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        complexity_count += 1

    if complexity_count < 3:
        flash('Password must contain at least 3 of: uppercase, lowercase, number, symbol.', 'danger')
        return redirect(url_for('blog_bp.admin'))

    # Check if user exists
    if User.query.filter_by(username=username).first():
        flash(f'Username "{username}" already exists.', 'danger')
        return redirect(url_for('blog_bp.admin'))

    if User.query.filter_by(email=email).first():
        flash(f'Email "{email}" is already registered.', 'danger')
        return redirect(url_for('blog_bp.admin'))

    # Create new user
    new_user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        is_active=is_active,
        is_admin=is_admin,
        is_approved=is_approved
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        flash(f'User {username} has been created successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating user: {e}")
        flash('An error occurred while creating the user.', 'danger')
    return redirect(url_for('blog_bp.admin'))

