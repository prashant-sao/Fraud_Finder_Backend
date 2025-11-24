from flask import Blueprint, jsonify, request, render_template
from flask_security import auth_required, current_user, login_user,logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from application.database import db
import requests
from bs4 import BeautifulSoup
import re
import logging

# Import your fraud detection modules

from application.agent.auto_reply import generate_auto_reply


from application.agent.risk_score import JobFraudDetector
from application.agent.job_recommendation import ml_recommender


fraud_detector = JobFraudDetector()

api_bp = Blueprint('api_bp', __name__)





# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@api_bp.route('/')
def index():
    return render_template('frontend/index.html')

@api_bp.route('/api/register', methods=['POST'])
def register():
    try:
        credentials = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'username', 'password']
        for field in required_fields:
            if not credentials.get(field):
                return jsonify({"message": f"{field} is required"}), 400
        
        # Check if user already exists
        if api_bp.security.datastore.find_user(email=credentials['email']):
            return jsonify({"message": "User already exists"}), 400
            
        if api_bp.security.datastore.find_user(username=credentials['username']):
            return jsonify({"message": "Username already taken"}), 400
        
        new_user = api_bp.security.datastore.create_user(
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

@api_bp.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')  # Changed from username to email
        password = data.get('password')

        if not email or not password:
            return jsonify({'message': 'Email and password are required!'}), 400

        # Find user by email
        user = api_bp.security.datastore.find_user(email=email)
        
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
        else:
            return jsonify({'message': 'Invalid email or password!'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'message': 'Login failed'}), 500

@api_bp.route('/api/logout', methods=['POST'])
def logout_simple():
    """Simple logout endpoint that doesn't require authentication"""
    try:
        # This version works even if the token has expired or is invalid
        logout_user()
        
        return jsonify({
            'message': 'Logout successful!',
            'success': True
        }), 200
        
    except Exception as e:
        logger.error(f"Simple logout error: {str(e)}")
        return jsonify({
            'message': 'Logout successful ',
            'success': True
        }), 200  

@api_bp.route('/api/edit_profile', methods=['PUT'])
@auth_required('token')
def edit_profile():
    try:
        data = request.get_json()
        user = api_bp.security.datastore.find_user(id=current_user.id)

        if 'username' in data:
            # Check if username is already taken by another user
            existing_user = api_bp.security.datastore.find_user(username=data['username'])
            if existing_user and existing_user.id != current_user.id:
                return jsonify({'message': 'Username already taken!'}), 400
            user.username = data['username']
            
        if 'email' in data:
            # Check if email is already taken by another user
            existing_user = api_bp.security.datastore.find_user(email=data['email'])
            if existing_user and existing_user.id != current_user.id:
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

def scrape_job_posting(url):
    """Scrape job posting content from URL"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
        
        # Get text content
        text = soup.get_text()
        
        # Clean up text
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = ' '.join(chunk for chunk in chunks if chunk)
        
        return text[:5000]  # Limit text length
        
    except requests.RequestException as e:
        logger.error(f"Scraping error: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected scraping error: {str(e)}")
        return None

@api_bp.route('/api/analyze', methods=['POST'])
def analyze_job_posting():
    """Main API endpoint for analyzing job postings"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        job_text = data.get('job_text', '').strip()
        job_url = data.get('job_url', '').strip()
        analysis_type = data.get('analysis_type', 'quick')  # 'quick' or 'detailed'
        user_id = data.get('user_id')  # Get user_id if provided
        
        # Determine input source
        if job_url:
            # Validate URL format
            url_pattern = re.compile(
                r'^https?://'  # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
                r'localhost|'  # localhost...
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                r'(?::\d+)?'  # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            
            if not url_pattern.match(job_url):
                return jsonify({'error': 'Invalid URL format'}), 400
            
            # Use the fraud_detector to fetch content from URL
            fetch_result = fraud_detector.fetch_job_posting(job_url)
            
            if not fetch_result['success']:
                return jsonify({'error': f'Failed to fetch job posting: {fetch_result["error"]}'}), 400
            
            job_text = fetch_result['content']
            
        elif not job_text:
            return jsonify({'error': 'Either job_text or job_url must be provided'}), 400
        
        # Set URL if not provided
        if not job_url:
            job_url = 'https://example.com/manual-entry'
        
        # Perform fraud analysis using the JobFraudDetector class
        # This will automatically save to database
        analysis_result = fraud_detector.analyze_job_posting(
            content=job_text,
            url=job_url,
            user_id=user_id,
            save_to_db=True
        )
        
        # Extract data from analysis_result
        risk_score = analysis_result['fraud_score']
        is_scam = risk_score >= 60  # Threshold for scam classification
        
        # Generate risk level
        if risk_score >= 80:
            risk_level = 'High'
            risk_color = 'danger'
        elif risk_score >= 40:
            risk_level = 'Medium'
            risk_color = 'warning'
        else:
            risk_level = 'Low'
            risk_color = 'success'
        
        # Generate auto-reply (you'll need to implement this function)
        auto_reply = generate_auto_reply(is_scam)
        
        # Prepare response matching your original format
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
        return jsonify({
            'success': False,
            'error': f'Analysis failed: {str(e)}'
        }), 500


# Helper function for generating auto-reply (implement as needed)
def generate_auto_reply(is_scam):
    """Generate automated reply based on scam detection"""
    if is_scam:
        return {
            'message': 'Warning: This job posting shows multiple fraud indicators. Exercise extreme caution.',
            'action': 'Do not proceed without thorough verification.'
        }
    else:
        return {
            'message': 'This job posting appears legitimate based on our analysis.',
            'action': 'Still verify company details independently before proceeding.'
        }


# Helper function for generating recommendations
def generate_recommendations(analysis_result, risk_score):
    """Generate recommendations based on analysis"""
    recommendations = []
    
    if analysis_result['red_flags'].get('no_company_website'):
        recommendations.append('Verify the company has a legitimate website')
    
    if analysis_result['red_flags'].get('no_linkedin'):
        recommendations.append('Check if the company has a LinkedIn presence')
    
    if analysis_result['red_flags'].get('suspicious_contact'):
        recommendations.append('Be cautious of personal email addresses for business communication')
    
    if analysis_result['red_flags'].get('unrealistic_salary'):
        recommendations.append('Verify salary claims are realistic for the position and industry')
    
    if analysis_result['red_flags'].get('requests_personal_details'):
        recommendations.append('NEVER provide sensitive personal information before proper verification')
    
    if risk_score >= 70:
        recommendations.append('Consider reporting this job posting to the platform')
        recommendations.append('Do not proceed with application')
    
    return recommendations




# Replace your existing /api/ml_recommend route with this:

@api_bp.route('/api/ml_recommend', methods=['POST'])
def ml_recommend():
    """
    Get personalized job recommendations with fraud analysis (Latest Alerts format)
    
    Request body:
    {
        "user_id": 123,                         // REQUIRED for personalization
        "limit": 10,                            // Optional - default 10, max 50
        "search_query": "python developer"      // Optional - overrides user preferences
    }
    
    Response (Latest Alerts format):
    {
        "success": true,
        "user_id": 123,
        "total_recommendations": 10,
        "safe_jobs_count": 6,
        "risky_jobs_count": 4,
        "search_query": null,
        "recommendations": [
            {
                "id": 1,
                "title": "Phishing Scam Alert",
                "subtitle": "Senior Developer at TechCorp",
                "description": "This job posting contains suspicious elements...",
                "risk_level": "High Risk",
                "risk_category": "Email",
                "fraud_score": 75,
                "time_ago": "2h ago",
                "job_url": "https://...",
                "is_read": false,
                "created_at": "2024-01-15T10:30:00"
            },
            ...
        ]
    }
    """
    try:
        data = request.get_json() or {}
        
        # Get parameters
        user_id = data.get('user_id')
        limit = data.get('limit', 10)
        search_query = data.get('search_query')
        
        # user_id is REQUIRED for personalized recommendations
        # if not user_id:
        #     return jsonify({
        #         'error': 'user_id is required for personalized recommendations'
        #     }), 400
        
        # Validate limit
        if not isinstance(limit, int) or limit < 1 or limit > 50:
            return jsonify({'error': 'limit must be between 1 and 50'}), 400
        
        logger.info(f"Getting personalized recommendations for user {user_id}: limit={limit}, query={search_query}")
        
        # Get personalized recommendations (unique for this user)
        recommendations = ml_recommender.get_recommendations(
            limit=limit,
            search_query=search_query,
            user_id=user_id
        )
        
        # Calculate statistics
        safe_count = sum(1 for rec in recommendations if rec.get('fraud_score', 0) < 30)
        risky_count = len(recommendations) - safe_count
        
        response_data = {
            'success': True,
            'user_id': user_id,
            'total_recommendations': len(recommendations),
            'safe_jobs_count': safe_count,
            'risky_jobs_count': risky_count,
            'search_query': search_query,
            'recommendations': recommendations
        }
        
        return jsonify(response_data), 200
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 404
        
    except Exception as e:
        logger.error(f"ML recommendation error: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': f'ML recommendation failed: {str(e)}'
        }), 500


# Add these additional routes for managing alerts:

@api_bp.route('/api/ml_recommend/history', methods=['GET'])
def get_alert_history():
    """
    Get user's alert history
    
    Query params:
    - user_id: required
    - limit: optional (default 20)
    - include_dismissed: optional (default false)
    """
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
            'alerts': [alert.to_dict() for alert in alerts]
        }), 200
        
    except Exception as e:
        logger.error(f"Get history error: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/api/ml_recommend/mark_read', methods=['POST'])
def mark_alert_read():
    """
    Mark an alert as read
    
    Request body:
    {
        "alert_id": 123,
        "user_id": 456
    }
    """
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
        
        return jsonify({
            'success': True,
            'message': 'Alert marked as read'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Mark read error: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/api/ml_recommend/dismiss', methods=['POST'])
def dismiss_alert():
    """
    Dismiss an alert
    
    Request body:
    {
        "alert_id": 123,
        "user_id": 456
    }
    """
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
        
        return jsonify({
            'success': True,
            'message': 'Alert dismissed'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Dismiss error: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
