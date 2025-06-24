"""ACME Bank web application."""

from datetime import datetime
import os
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, 
    url_for, session, flash, send_file, jsonify, make_response
)
import sys

from aws.secrets import SecretsClient
from database.database import Database
from services.auth_service import AuthService
from services.account_service import AccountService
from services.transaction_service import TransactionService
from services.input_validation import InputValidator, InputValidationError
from services.password_service import PasswordService
from services.rate_limiter import RateLimiter
from services.csrf import generate_csrf_token, csrf_protect

class Application:
    """Main application class handling all banking operations."""

    def __init__(self):
        self.app_dir = os.path.dirname(os.path.abspath(__file__))
        self.app = Flask(
            __name__,
            template_folder=os.path.join(self.app_dir, 'templates'),
            static_folder=os.path.join(self.app_dir, 'static')
        )

        self._init_secrets()
        self._configure_app()
        self._init_services()
        self._register_routes()
        self._register_template_filters()

        @self.app.before_request
        def before_request():
            if 'csrf_token' not in session:
                generate_csrf_token()

        @self.app.context_processor
        def inject_csrf_token():
            if 'csrf_token' not in session:
                generate_csrf_token()
            return dict(csrf_token=generate_csrf_token)

        self.rate_limiter = RateLimiter()

    def _init_secrets(self):
        try:
            self.secrets_client = SecretsClient()
            secrets = self.secrets_client.get_secret('ACME-Web-App')
            if not secrets:
                raise ValueError("Failed to load application secrets")
            self.app.secret_key = secrets['SECRET_KEY']
        except Exception as e:
            raise RuntimeError(f"Secrets initialisation failed: {e}")

    def _configure_app(self):
        self.app.config['ASSET_FOLDER'] = os.path.abspath(
            os.path.join(self.app_dir, 'static', 'statements')
        )
        
        self.app.config.update(
            ENV='production',
            SERVER_NAME=None,
            PREFERRED_URL_SCHEME='https'
        )
        
        self.app.jinja_env.globals['csrf_token'] = generate_csrf_token
        
        @self.app.after_request
        def add_security_headers(response):
            response.headers.pop('Server', None)
            response.headers.pop('X-Powered-By', None)
            response.headers.pop('X-Runtime', None)
            
            csp_directives = [
                "default-src 'self'",
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://stackpath.bootstrapcdn.com https://ajax.googleapis.com https://cdn.jsdelivr.net",
                "style-src 'self' 'unsafe-inline' https://stackpath.bootstrapcdn.com",
                "img-src 'self' data: https: blob:",
                "font-src 'self' https://stackpath.bootstrapcdn.com",
                "connect-src 'self'",
                "media-src 'self'",
                "object-src 'none'",
                "frame-src 'self'",
                "frame-ancestors 'none'",
                "form-action 'self'",
                "base-uri 'self'",
                "manifest-src 'self'",
                "upgrade-insecure-requests",
                "block-all-mixed-content"
            ]

            security_headers = {
                'Content-Security-Policy': '; '.join(csp_directives),
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                'X-Content-Type-Options': 'nosniff',
                'Frame-Options': 'DENY',
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
                'Referrer-Policy': 'strict-origin-when-cross-origin',
                'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
                'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                'Pragma': 'no-cache'
            }

            for header, value in security_headers.items():
                response.headers[header] = value

            if 'Set-Cookie' in response.headers:
                cookies = response.headers.getlist('Set-Cookie')
                response.headers.pop('Set-Cookie')
                for cookie in cookies:
                    if 'HttpOnly' not in cookie:
                        cookie += '; HttpOnly'
                    if 'Secure' not in cookie:
                        cookie += '; Secure'
                    if 'SameSite' not in cookie:
                        cookie += '; SameSite=Strict'
                    response.headers.add('Set-Cookie', cookie)

            return response

        self.app.config.update(
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_SAMESITE='Strict',
            PERMANENT_SESSION_LIFETIME=1800,
            SESSION_PROTECTION='strong'
        )

        os.makedirs(self.app.config['ASSET_FOLDER'], exist_ok=True)

    def _init_services(self):
        try:
            self.db = Database()
            self.input_validator = InputValidator()
            self.password_service = PasswordService()
            self.auth_service = AuthService(self.db)
            self.account_service = AccountService(self.db)
            self.transaction_service = TransactionService(self.db)
        except Exception as e:
            raise RuntimeError(f"Service initialisation failed: {e}")

    def _register_routes(self):
        @self.app.route('/')
        def index():
            if self.auth_service.is_authenticated():
                return redirect(url_for('dashboard'))
            return render_template('login.html')

        @self.app.route('/login', methods=['GET', 'POST'])
        @csrf_protect
        def login():
            if request.method == 'POST':
                try:
                    username = request.form.get('username')
                    password = request.form.get('password')

                    if self.auth_service.login(username, password):
                        session.pop('csrf_token', None)
                        generate_csrf_token()
                        
                        flash('Login successful', 'success')
                        return redirect(url_for('dashboard'))

                    flash('Invalid credentials', 'danger')
                    return redirect(url_for('login'))

                except Exception as e:
                    flash('An error occurred during login', 'danger')
                    return redirect(url_for('login'))

            if 'csrf_token' not in session:
                generate_csrf_token()
            
            return render_template('login.html')

        @self.app.route('/dashboard')
        def dashboard():
            if not self.auth_service.is_authenticated():
                return redirect(url_for('login'))
            
            user_id = session.get('user_id')
            accounts = self.account_service.get_user_accounts(user_id)
            return render_template('dashboard.html', 
                                accounts=accounts, 
                                username=session.get('username'))

        @self.app.route('/transfer', methods=['GET'])
        @csrf_protect
        def transfer_form():
            if not self.auth_service.is_authenticated():
                return redirect(url_for('login'))
            
            user_id = session.get('user_id')
            username = session.get('username')
            query = 'SELECT id, name FROM account_types WHERE id!=0'
            account_types = self.db.execute_query(query)
            
            return render_template('transfer.html', 
                                username=username, 
                                account_types=account_types)

        @self.app.route('/transfer', methods=['POST'])
        def transfer():
            if not self.auth_service.is_authenticated():
                return redirect(url_for('login'))
            
            try:
                user_id = session.get('user_id')
                from_account_type = int(request.form['from_account'])
                to_account_type = int(request.form['to_account'])
                amount = float(request.form['amount'])

                if from_account_type == to_account_type:
                    flash('Cannot transfer to the same account type.', 'danger')
                    return redirect(url_for('transfer_form'))

                if amount <= 0:
                    flash('Amount must be greater than zero.', 'danger')
                    return redirect(url_for('transfer_form'))

                from_account = self.account_service.get_account_for_user(user_id, from_account_type)
                to_account = self.account_service.get_account_for_user(user_id, to_account_type)

                if not from_account or not to_account:
                    flash('Invalid account selection.', 'danger')
                    return redirect(url_for('transfer_form'))

                if from_account[3] < amount:
                    flash('Insufficient funds for transfer.', 'danger')
                    return redirect(url_for('transfer_form'))

                success = self.transaction_service.transfer_funds(
                    user_id=user_id,
                    from_account=from_account[0],
                    to_account=to_account[0],
                    transaction_type='TRANSFER',
                    amount=amount
                )
                
                if success:
                    flash(f'Successfully transferred £{amount:,.2f}', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Transfer failed. Please try again.', 'danger')
                    
            except ValueError:
                flash('Invalid input values.', 'danger')
            except Exception as e:
                flash('An error occurred during transfer.', 'danger')
                
            return redirect(url_for('transfer_form'))

        @self.app.route('/pay', methods=['GET'])
        @csrf_protect
        def pay_form():
            if not self.auth_service.is_authenticated():
                return redirect(url_for('login'))
            
            username = session.get('username')
            query = "SELECT id, name FROM account_types WHERE id != 0"
            account_types = self.db.execute_query(query)
            
            return render_template('pay.html', 
                                username=username, 
                                accounts=account_types)

        @self.app.route('/pay', methods=['POST'])
        def pay():
            if not self.auth_service.is_authenticated():
                return redirect(url_for('login'))
            
            try:
                user_id = session.get('user_id')
                username = session.get('username')
                
                payment_data = {
                    'from_account': request.form['from_account'],
                    'recipient_email': request.form['recipient_email'],
                    'amount': request.form['amount'],
                    'reference': request.form['reference']
                }
                
                try:
                    validated_data = self.input_validator.validate_payment_input(payment_data)
                except InputValidationError as e:
                    flash(f'Invalid input: {str(e)}', 'danger')
                    return redirect(url_for('pay_form'))
                
                from_account_type = int(validated_data.get('from_account', payment_data['from_account']))
                recipient_email = validated_data.get('recipient_email')
                amount = float(validated_data.get('amount'))
                reference = validated_data.get('reference', '')

                from_account = self.account_service.get_account_for_user(user_id, from_account_type)
                to_account = self.account_service.get_account_for_email(recipient_email)

                if not from_account or not to_account:
                    flash('Invalid account details.', 'danger')
                    return redirect(url_for('pay_form'))

                if from_account[3] < amount:
                    flash('Insufficient balance for the payment.', 'danger')
                    return redirect(url_for('pay_form'))

                success = self.transaction_service.transfer_funds(
                    user_id=user_id,
                    from_account=from_account[0],
                    to_account=to_account[0],
                    transaction_type='PAYMENT',
                    amount=amount,
                    reference=reference
                )
                
                if success:
                    flash(f'Paid {recipient_email} - £{amount:,.2f}', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Payment failed. Please try again.', 'danger')
                    
                return redirect(url_for('pay_form'))
                    
            except Exception as e:
                flash('An error occurred during payment.', 'danger')
                return redirect(url_for('pay_form'))

        @self.app.route('/statements')
        def statement():
            if not self.auth_service.is_authenticated():
                return redirect(url_for('login'))
            
            user_id = session.get('user_id')
            username = session.get('username')
            
            try:
                statement_data = self.transaction_service.get_statement(user_id)
                
                if not statement_data:
                    flash('No transactions found.', 'info')
                    return render_template('statement.html',
                                        username=username,
                                        userid=user_id,
                                        transactions=[])
                
                filename = self._generate_csv(statement_data, user_id, username)
                
                return render_template('statement.html',
                                    username=username,
                                    userid=user_id,
                                    transactions=statement_data)

            except Exception as e:
                flash('Error retrieving statement.', 'danger')
                return redirect(url_for('dashboard'))

        @self.app.route('/api/check_user_exists', methods=['GET'])
        @require_api_auth(limit_type='default')
        def check_user_exists():
            try:
                recipient_username = request.args.get('recipient_username')
                
                if not recipient_username:
                    return jsonify({
                        'error': 'Bad Request',
                        'message': 'Username is required'
                    }), 400

                try:
                    recipient_username = self.input_validator.sanitise_input(recipient_username)
                except InputValidationError as e:
                    return jsonify({
                        'error': 'Bad Request',
                        'message': str(e)
                    }), 400

                user_id = session.get('user_id')
                query = '''
                    SELECT COUNT(*) 
                    FROM users u
                    INNER JOIN accounts a_to ON a_to.user_id = u.id
                    INNER JOIN transactions t ON t.to_account = a_to.id
                    INNER JOIN accounts a_from ON t.from_account = a_from.id
                    WHERE a_from.user_id = ? 
                    AND u.username = ?
                '''
                
                result = self.db.execute_query(query, (user_id, recipient_username))
                
                return jsonify({
                    'exists': result[0][0] > 0
                })

            except Exception as e:
                return jsonify({
                    'error': 'Internal Server Error',
                    'message': 'An error occurred processing your request'
                }), 500

        @self.app.route('/api/search_users', methods=['GET'])
        @require_api_auth(limit_type='search')
        def search_users():
            try: 
                search_query = request.args.get('search_query')
                
                if not search_query:
                    return jsonify({
                        'error': 'Bad Request',
                        'message': 'Search query is required'
                    }), 400

                try:
                    search_query = self.input_validator.validate_search_input(search_query)
                except InputValidationError as e:
                    return jsonify({
                        'error': 'Bad Request',
                        'message': str(e)
                    }), 400

                user_id = session.get('user_id')
                query = '''
                    SELECT id, username, firstname, lastname, email 
                    FROM users 
                    WHERE email = ? 
                    AND id != ?
                    LIMIT 1
                '''
                
                result = self.db.execute_query(query, (search_query, user_id))

                if not result:
                    return jsonify({
                        'error': 'Not Found',
                        'message': 'No matching user found'
                    }), 404

                user = result[0]
                user_data = {
                    'id': user[0],
                    'username': self._mask_sensitive_data(user[1]),
                    'firstname': user[2],
                    'lastname': user[3],
                    'email': user[4],
                    'fullname': f"{user[2]} {user[3]}"
                }

                return jsonify({
                    'message': 'User found',
                    'data': user_data
                })

            except Exception as e:
                return jsonify({
                    'error': 'Internal Server Error',
                    'message': 'An error occurred processing your request'
                }), 500

        @self.app.route('/statements/asset')
        def get_asset():
            if not self.auth_service.is_authenticated():
                return redirect(url_for('login'))
            
            asset_name = request.args.get('asset_name')
            if not asset_name:
                return 'File not found', 404
            
            try:
                if not self.input_validator.is_valid_filename(asset_name):
                    return 'Invalid filename', 400
                    
                user_id = session.get('user_id')
                if not self._verify_file_access(user_id, asset_name):
                    return 'Unauthorised to download file', 403
                    
                file_path = self.safe_path_join(self.app.config['ASSET_FOLDER'], asset_name)
                
                if not os.path.exists(file_path):
                    return 'File not found', 404
                    
                return send_file(file_path, as_attachment=True)
            except SecurityError:
                return 'Invalid path', 400
            except Exception:
                return 'File not found', 404

        @self.app.route('/profile', methods=['GET', 'POST'])
        @csrf_protect
        def edit_profile():
            if not self.auth_service.is_authenticated():
                return redirect(url_for('login'))
                    
            username = session.get('username')
            user_id = session.get('user_id')
            
            if 'csrf_token' not in session:
                generate_csrf_token()
            
            if request.method == 'POST':
                token = session.get('csrf_token')
                if not token or token != request.form.get('csrf_token'):
                    flash('Security validation failed. Please try again.', 'danger')
                    return redirect(url_for('login'))
                    
                new_email = request.form['email']
                new_firstname = request.form['firstname']
                new_lastname = request.form['lastname']
                new_password = request.form['password']
                
                current_session = dict(session)
                
                try:
                    current_password = self.db.execute_query(
                        "SELECT password FROM users WHERE username = ?", 
                        (username,)
                    )[0][0]
                    
                    password_to_store = (self.password_service.hash_password(new_password) 
                                       if not all(c == '*' for c in new_password)
                                       else current_password)
                    
                    query = '''
                        UPDATE users
                        SET email = ?, firstname = ?, lastname = ?, password = ?
                        WHERE username = ?
                    '''
                    self.db.execute_query(query, (
                        new_email, 
                        new_firstname, 
                        new_lastname, 
                        password_to_store, 
                        username
                    ))

                    session.pop('csrf_token', None)
                    generate_csrf_token()

                    for key, value in current_session.items():
                        if key != 'csrf_token':
                            session[key] = value
                    
                    flash('Profile updated successfully.', 'success')
                    return redirect(url_for('dashboard'))
                    
                except Exception:
                    flash('Error updating profile.', 'danger')
                    return redirect(url_for('edit_profile'))
            
            query = 'SELECT email, firstname, lastname, password FROM users WHERE username = ?'
            profile_data = self.db.execute_query(query, (username,))
            
            if profile_data:
                profile_data = profile_data[0]
                user_profile = {
                    'email': profile_data[0],
                    'firstname': profile_data[1],
                    'lastname': profile_data[2],
                    'password': '*' * 40
                }
                return render_template('edit_profile.html', 
                                    username=username, 
                                    user_profile=user_profile,
                                    csrf_token=session.get('csrf_token'))
            
            flash('Profile not found.', 'danger')
            return redirect(url_for('dashboard'))

        @self.app.route('/logout')
        def logout():
            self.auth_service.logout()
            flash('You have been logged out.', 'info')
            return redirect(url_for('login'))

        @self.app.errorhandler(404)
        def not_found_error(error):
            try:
                return render_template('404.html'), 404
            except:
                return 'Page not found', 404

        @self.app.errorhandler(500)
        def internal_error(error):
            try:
                return render_template('500.html'), 500
            except:
                return 'Internal server error', 500

    def _register_template_filters(self):
        @self.app.template_filter()
        def formatdatetime(value: str, date_format='%Y-%m-%d %H:%M:%S'):
            try:
                date_time = datetime.strptime(value, date_format)
                return date_time.strftime("%d-%m-%Y")
            except ValueError:
                return value

    def _generate_csv(self, statement, userid, username):
        filename = f'user_{userid}_bank_statement.csv'
        path = self.safe_path_join(
            self.app.config['ASSET_FOLDER'], 
            filename
        )
        
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        try:
            with open(path, 'w') as f:
                for transaction in statement:
                    f.write(",".join([str(c) for c in transaction]) + "\n")
                    
            return filename
        except Exception as e:
            raise

    def safe_path_join(self, base_path, filename):
        safe_path = os.path.normpath(os.path.join(base_path, filename))
        if not safe_path.startswith(base_path):
            raise SecurityError("Invalid path detected")
        return safe_path

    def _verify_file_access(self, user_id, filename):
        expected_filename = f'user_{user_id}_bank_statement.csv'
        return filename == expected_filename
    
    def _mask_sensitive_data(self, data: str) -> str:
        if not data:
            return ''
        return data[:2] + '*' * (len(data) - 2)
    
    def run(self, host: str = '0.0.0.0', port: int = 8081, debug: bool = True):
        cli = sys.modules['flask.cli']
        cli.show_server_banner = lambda *x: None
        
        from werkzeug.serving import WSGIRequestHandler
        WSGIRequestHandler.server_version = ""
        WSGIRequestHandler.sys_version = ""
        
        self.app.run(host=host, port=port, debug=debug)


class SecurityError(Exception):
    pass

def require_api_auth(limit_type='default'):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get('user_id'):
                return jsonify({
                    'error': 'Unauthorised',
                    'message': 'Authentication required'
                }), 401

            user_id = session.get('user_id')
            allowed, limit_info = application.rate_limiter.is_allowed(str(user_id), limit_type)
            
            response_headers = {
                'X-RateLimit-Limit': str(limit_info.get('limit', '')),
                'X-RateLimit-Remaining': str(limit_info.get('remaining', '')),
                'X-RateLimit-Reset': str(limit_info.get('reset', ''))
            }
            
            if not allowed:
                response = jsonify({
                    'error': 'Too Many Requests',
                    'message': 'Rate limit exceeded',
                    'retry_after': limit_info.get('retry_after')
                })
                
                response.headers.extend(response_headers)
                response.headers['Retry-After'] = str(limit_info.get('retry_after', 60))
                
                return response, 429
            
            response = make_response(f(*args, **kwargs))
            response.headers.extend(response_headers)
            
            return response
            
        return decorated
    return decorator

application = Application()

if __name__ == '__main__':
    application.run(debug=False)
