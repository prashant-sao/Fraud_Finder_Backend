from flask import Blueprint, jsonify, request, render_template
from flask_security import auth_required, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from application.database import db
from application import security  # IMPORTANT FIX
import requests
from bs4 import BeautifulSoup
import re
import logging

# Import your fraud detection & ML modules
from application.agent.auto_reply import generate_auto_reply
from application.agent.risk_score import JobFraudDetector
from application.agent.job_recommendation import ml_recommender

fraud_detector = JobFraudDetector()

api_bp = Blueprint('api_bp', __name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================
#      USER REGISTRATION
# ============================
@api_bp.route('/api/register', methods=['POST'])
def register():
    try:
        credentials = request.get_json()

        required_fields = ['email', 'username', 'password']
        for field in required_fields:
            if not credentials.get(field):
                return jsonify({"message": f"{field} is required"}), 400

        # CHECK EMAIL + USERNAME
        if security.datastore.find_user(email=credentials['email']):
            return jsonify({"message": "User already exists"}), 400

        if security.datastore.find_user(username=credentials['username']):
            return jsonify({"message": "Username already taken"}), 400

        new_user = security.datastore.create_user(
            email=credentials['email'],
            username=credentials['username'],
            password=generate_password_hash(credentials['password']),
            qualifications=credentials.get('qualification', ''),
            fields_of_interest=credentials.get('fields_of_interest', '')
        )

        db.session.commit()
        return jsonify({"message": "User registered successfully"}), 201

    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({"message": "Registration failed"}), 500


# ============================
#            LOGIN
# ============================
@api_bp.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'message': 'Email and password are required!'}), 400

        user = security.datastore.find_user(email=email)

        if user and check_password_hash(user.password, password):
            login_user(user)
            return jsonify({
                'message': 'Login successful!',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                }
            }), 200

        return jsonify({'message': 'Invalid email or password!'}), 401

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'message': 'Login failed'}), 500


# ============================
#            LOGOUT
# ============================
@api_bp.route('/api/logout', methods=['POST'])
def logout_simple():
    try:
        logout_user()
        return jsonify({'message': 'Logout successful!', 'success': True}), 200
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({'message': 'Logout successful', 'success': True}), 200


# ============================
#        EDIT PROFILE
# ============================
@api_bp.route('/api/edit_profile', methods=['PUT'])
@auth_required('token')
def edit_profile():
    try:
        data = request.get_json()
        user = security.datastore.find_user(id=current_user.id)

        if 'username' in data:
            existing = security.datastore.find_user(username=data['username'])
            if existing and existing.id != current_user.id:
                return jsonify({'message': 'Username already taken!'}), 400
            user.username = data['username']

        if 'email' in data:
            existing = security.datastore.find_user(email=data['email'])
            if existing and existing.id != current_user.id:
                return jsonify({'message': 'Email already taken!'}), 400
            user.email = data['email']

        if 'password' in data:
            user.password = generate_password_hash(data['password'])

        if 'qualifications' in data:
            user.qualifications = data['qualifications']

        if 'fields_of_interest' in data:
            user.fields_of_interest = data['fields_of_interest']

        db.session.commit()
        return jsonify({'message': 'Profile updated successfully!'}), 200

    except Exception as e:
        logger.error(f"Profile update error: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Profile update failed'}), 500


# ============================
#   SCRAPE JOB POSTING
# ============================
def scrape_job_posting(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, 'html.parser')

        for script in soup(["script", "style"]):
            script.decompose()

        text = soup.get_text()
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split(" "))
        text = ' '.join(chunk for chunk in chunks if chunk)

        return text[:5000]

    except Exception as e:
        logger.error(f"Scraping error: {str(e)}")
        return None


# ============================
#     ANALYZE JOB POSTING
# ============================
@api_bp.route('/api/analyze', methods=['POST'])
def analyze_job_posting():
    try:
        data = request.get_json()

        job_text = data.get('job_text', '').strip()
        job_url = data.get('job_url', '').strip()
        analysis_type = data.get('analysis_type', 'quick')
        user_id = data.get('user_id')

        # If URL provided → validate + fetch
        if job_url:
            pattern = re.compile(
                r'^https?://'
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}|localhost|\d{1,3}(?:\.\d{1,3}){3})'
                r'(?::\d+)?(?:/?|[/?]\S+)$',
                re.IGNORECASE
            )
            if not pattern.match(job_url):
                return jsonify({'error': 'Invalid URL format'}), 400

            fetch = fraud_detector.fetch_job_posting(job_url)
            if not fetch['success']:
                return jsonify({'error': f"Failed to fetch job posting: {fetch['error']}"}), 400

            job_text = fetch['content']

        elif not job_text:
            return jsonify({'error': 'Either job_text or job_url must be provided'}), 400

        if not job_url:
            job_url = 'https://example.com/manual-entry'

        analysis_result = fraud_detector.analyze_job_posting(
            content=job_text,
            url=job_url,
            user_id=user_id,
            save_to_db=True
        )

        risk_score = analysis_result['fraud_score']
        is_scam = risk_score >= 60

        risk_level = (
            "High" if risk_score >= 80 else
            "Medium" if risk_score >= 40 else "Low"
        )
        risk_color = (
            "danger" if risk_score >= 80 else
            "warning" if risk_score >= 40 else "success"
        )

        auto_reply = generate_auto_reply(is_scam)

        response_data = {
            'success': True,
            'url': job_url,
            'job_id': analysis_result.get('job_id'),
            'analysis_id': analysis_result.get('analysis_id'),
            'job_title': analysis_result['job_title'],
            'fraud_score': risk_score,
            'verdict': analysis_result['verdict'],
            'risk_level': analysis_result['risk_level'],
            'risk_color': risk_color,
            'is_scam': is_scam,
            'auto_reply': auto_reply,
            'red_flags': analysis_result['red_flags'],
            'details': analysis_result['details'],
            'analysis': {
                'red_flags': analysis_result['red_flags'],
                'company_legitimacy': {
                    'has_website': not analysis_result['red_flags'].get('no_company_website', True),
                    'has_linkedin': not analysis_result['red_flags'].get('no_linkedin', True),
                    'company_info_present': not analysis_result['red_flags'].get('no_company_info', True)
                },
                'company_info': {
                    'name': analysis_result.get('company_name'),
                    'website': analysis_result['details'].get('company_website')
                }
            },
            'recommendations': generate_recommendations(analysis_result, risk_score),
            'analysis_type': analysis_type
        }

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        return jsonify({'success': False, 'error': f'Analysis failed: {str(e)}'}), 500


# ============================
#   RECOMMENDATION LOGIC
# ============================
def generate_recommendations(analysis_result, risk_score):
    recommendations = []

    if analysis_result['red_flags'].get('no_company_website'):
        recommendations.append('Verify the company has a legitimate website')

    if analysis_result['red_flags'].get('no_linkedin'):
        recommendations.append('Check if the company has a LinkedIn presence')

    if analysis_result['red_flags'].get('suspicious_contact'):
        recommendations.append('Be cautious of personal email addresses')

    if analysis_result['red_flags'].get('unrealistic_salary'):
        recommendations.append('Verify salary claims with industry standards')

    if analysis_result['red_flags'].get('requests_personal_details'):
        recommendations.append('Never provide sensitive information prematurely')

    if risk_score >= 70:
        recommendations.append('Consider reporting this job posting')
        recommendations.append('Avoid proceeding with this application')

    return recommendations


# =========================================
#         ML RECOMMENDATION SYSTEM
# =========================================
@api_bp.route('/api/ml_recommend', methods=['POST'])
def ml_recommend():
    try:
        data = request.get_json() or {}

        user_id = data.get('user_id')
        limit = data.get('limit', 10)
        search_query = data.get('search_query')

        if not isinstance(limit, int) or not (1 <= limit <= 50):
            return jsonify({'error': 'limit must be between 1 and 50'}), 400

        logger.info(f"ML Recommend => user={user_id}, limit={limit}, query={search_query}")

        recommendations = ml_recommender.get_recommendations(
            limit=limit,
            search_query=search_query,
            user_id=user_id
        )

        safe_count = sum(1 for rec in recommendations if rec.get('fraud_score', 0) < 30)
        risky_count = len(recommendations) - safe_count

        return jsonify({
            'success': True,
            'user_id': user_id,
            'total_recommendations': len(recommendations),
            'safe_jobs_count': safe_count,
            'risky_jobs_count': risky_count,
            'search_query': search_query,
            'recommendations': recommendations
        }), 200

    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 404

    except Exception as e:
        logger.error(f"ML recommendation error: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': f"ML recommendation failed: {str(e)}"}), 500


# =========================================
#         ALERT HISTORY
# =========================================
@api_bp.route('/api/ml_recommend/history', methods=['GET'])
def get_alert_history():
    try:
        from application.models import User_Job_Alerts

        user_id = request.args.get('user_id', type=int)
        limit = request.args.get('limit', 20, type=int)
        include_dismissed = request.args.get('include_dismissed', 'false').lower() == 'true'

        if not user_id:
            return jsonify({'error': 'user_id is required'}), 400

        query = User_Job_Alerts.query.filter_by(user_id=user_id)

        if not include_dismissed:
            query = query.filter_by(is_dismissed=False)

        alerts = query.order_by(User_Job_Alerts.created_at.desc()).limit(limit).all()

        return jsonify({
            'success': True,
            'user_id': user_id,
            'total_alerts': len(alerts),
            'alerts': [a.to_dict() for a in alerts]
        }), 200

    except Exception as e:
        logger.error(f"Get history error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


# =========================================
#           MARK ALERT AS READ
# =========================================
@api_bp.route('/api/ml_recommend/mark_read', methods=['POST'])
def mark_alert_read():
    try:
        from application.models import User_Job_Alerts

        data = request.get_json()
        alert_id = data.get('alert_id')
        user_id = data.get('user_id')

        if not alert_id or not user_id:
            return jsonify({'error': 'alert_id and user_id are required'}), 400

        alert = User_Job_Alerts.query.filter_by(id=alert_id, user_id=user_id).first()

        if not alert:
            return jsonify({'error': 'Alert not found'}), 404

        alert.is_read = True
        db.session.commit()

        return jsonify({'success': True, 'message': 'Alert marked as read'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# =========================================
#           DISMISS ALERT
# =========================================
@api_bp.route('/api/ml_recommend/dismiss', methods=['POST'])
def dismiss_alert():
    try:
        from application.models import User_Job_Alerts

        data = request.get_json()
        alert_id = data.get('alert_id')
        user_id = data.get('user_id')

        if not alert_id or not user_id:
            return jsonify({'error': 'alert_id and user_id are required'}), 400

        alert = User_Job_Alerts.query.filter_by(id=alert_id, user_id=user_id).first()

        if not alert:
            return jsonify({'error': 'Alert not found'}), 404

        alert.is_dismissed = True
        db.session.commit()

        return jsonify({'success': True, 'message': 'Alert dismissed'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
