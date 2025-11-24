from application.database import db
from flask_security import UserMixin, RoleMixin
from datetime import datetime

class User(db.Model, UserMixin):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    qualifications = db.Column(db.String(120), nullable=True)
    fields_of_interest = db.Column(db.String(250), nullable=True)
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)
    active = db.Column(db.Boolean(), default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    roles = db.relationship('Role', secondary='user_roles', backref=db.backref('users', lazy='dynamic'))
    job_postings = db.relationship('Job_Posting', backref='user', lazy=True)
    community_reports = db.relationship(
        'Community_Reports',
        backref='reporter',
        lazy=True,
        foreign_keys='Community_Reports.user_id'  # Specify which foreign key to use
    )
    # Add a new relationship for reviews if needed
    reviews = db.relationship(
        'Community_Reports',
        backref='reviewer',
        lazy=True,
        foreign_keys='Community_Reports.reviewed_by'
    )

    def __repr__(self):
        return f'<User {self.username}>'


class Role(db.Model, RoleMixin):
    __tablename__ = 'Role'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __repr__(self):
        return f'<Role {self.name}>'


class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer, db.ForeignKey('Role.id', ondelete='CASCADE'))


class Job_Posting(db.Model):
    __tablename__ = 'Job_Posting'
    job_id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)  # Increased length for long URLs
    company_name = db.Column(db.String(100), nullable=False, index=True)
    job_title = db.Column(db.String(150), nullable=False, index=True)
    job_description = db.Column(db.Text, nullable=False)
    extracted_entities = db.Column(db.Text, nullable=True)  # JSON stored as text
    submitted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    submitted_by = db.Column(db.Integer, db.ForeignKey('User.id', ondelete='SET NULL'), nullable=True)
    
    # New fields for better tracking
    location = db.Column(db.String(200), nullable=True)
    salary_range = db.Column(db.String(100), nullable=True)
    
    # Relationships
    analysis_results = db.relationship('Analysis_Results', backref='job', lazy=True, cascade='all, delete-orphan')
    community_reports = db.relationship('Community_Reports', backref='job', lazy=True, cascade='all, delete-orphan')
    trending = db.relationship('Trending_Fraud_Job', backref='job', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Job_Posting {self.job_id}: {self.job_title}>'


class Trending_Fraud_Job(db.Model):
    __tablename__ = 'Trending_Fraud_Job'
    trend_id = db.Column(db.Integer, primary_key=True)
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    popularity_score = db.Column(db.Float, nullable=False, default=0.0)
    view_count = db.Column(db.Integer, default=0)  # Track how many times viewed
    report_count = db.Column(db.Integer, default=0)  # Track number of reports
    job_id = db.Column(db.Integer, db.ForeignKey('Job_Posting.job_id', ondelete='CASCADE'), nullable=False, unique=True)
    fields_of_interest = db.Column(db.String(250), nullable=True)

    def __repr__(self):
        return f'<Trending_Fraud_Job {self.trend_id}: Job {self.job_id}>'


class Analysis_Results(db.Model):
    __tablename__ = 'analysis_results'
    analysis_id = db.Column(db.Integer, primary_key=True)
    risk_score = db.Column(db.Float, nullable=False, index=True)
    summary_labels = db.Column(db.Text, nullable=True)  # JSON array of red flags
    analyzed_at = db.Column(db.DateTime, default=datetime.utcnow)
    verdict = db.Column(db.String(50), nullable=True)  # "Likely Fraudulent", etc.
    risk_level = db.Column(db.String(50), nullable=True)  # "High Risk", etc.
    job_id = db.Column(db.Integer, db.ForeignKey('Job_Posting.job_id', ondelete='CASCADE'), nullable=False)
    
    # Relationships
    fraud_indicators = db.relationship('Fraud_Indicators', backref='analysis', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Analysis_Results {self.analysis_id}: Score {self.risk_score}>'


class Company_Verification(db.Model):
    __tablename__ = 'company_verification'
    company_id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(100), nullable=False, unique=True, index=True)
    linkedin_url = db.Column(db.String(300), nullable=True)
    website_url = db.Column(db.String(300), nullable=True)
    social_presence = db.Column(db.Boolean, nullable=False, default=False)
    reputation_score = db.Column(db.Float, nullable=False, default=50.0)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    verification_date = db.Column(db.DateTime, nullable=True)
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Additional verification fields
    website_accessible = db.Column(db.Boolean, default=False)
    email_domain = db.Column(db.String(100), nullable=True)
    total_jobs_posted = db.Column(db.Integer, default=0)
    fraud_jobs_count = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<Company_Verification {self.company_name}>'


class Community_Reports(db.Model):
    __tablename__ = 'community_reports'
    report_id = db.Column(db.Integer, primary_key=True)
    report_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    report_reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='pending')  # pending, reviewed, confirmed, dismissed
    job_id = db.Column(db.Integer, db.ForeignKey('Job_Posting.job_id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('User.id', ondelete='SET NULL'),
        nullable=True
    )
    reviewed_by = db.Column(
        db.Integer,
        db.ForeignKey('User.id', ondelete='SET NULL'),
        nullable=True
    )
    
    # Additional context
    user_experience = db.Column(db.Text, nullable=True)  # User's experience with this job
    reviewed_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<Community_Reports {self.report_id}: Job {self.job_id}>'


class Fraud_Indicators(db.Model):
    __tablename__ = 'fraud_indicators'
    indicator_id = db.Column(db.Integer, primary_key=True)
    indicator_type = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    severity_level = db.Column(db.String(50), nullable=False)  # Low, Medium, High, Critical
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    analysis_id = db.Column(db.Integer, db.ForeignKey('analysis_results.analysis_id', ondelete='CASCADE'), nullable=False)
    
    # Additional context
    confidence_score = db.Column(db.Float, default=1.0)  # 0.0 to 1.0
    matched_pattern = db.Column(db.Text, nullable=True)  # What pattern/keyword triggered this

    def __repr__(self):
        return f'<Fraud_Indicators {self.indicator_id}: {self.indicator_type}>'


# New model for tracking search queries and analytics
class Search_Analytics(db.Model):
    __tablename__ = 'search_analytics'
    search_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id', ondelete='SET NULL'), nullable=True)
    search_query = db.Column(db.String(500), nullable=False)
    search_date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    results_count = db.Column(db.Integer, default=0)
    filters_applied = db.Column(db.Text, nullable=True)  # JSON

    def __repr__(self):
        return f'<Search_Analytics {self.search_id}>'


class User_Job_Alerts(db.Model):
    """Store personalized job alerts for each user"""
    __tablename__ = 'user_job_alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id', ondelete='CASCADE'), nullable=False, index=True)
    alert_title = db.Column(db.String(200), nullable=False)
    alert_subtitle = db.Column(db.String(300), nullable=True)
    alert_description = db.Column(db.Text, nullable=False)
    risk_level = db.Column(db.String(50), nullable=False)
    risk_category = db.Column(db.String(100), nullable=False)
    fraud_score = db.Column(db.Integer, default=0)
    job_title = db.Column(db.String(200), nullable=True)
    job_company = db.Column(db.String(200), nullable=True)
    job_url = db.Column(db.String(500), nullable=False)
    job_source = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_read = db.Column(db.Boolean, default=False)
    is_dismissed = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref=db.backref('job_alerts', lazy='dynamic'))
    
    def to_dict(self):
        from datetime import timedelta
        time_diff = datetime.utcnow() - self.created_at
        if time_diff < timedelta(minutes=60):
            time_ago = f"{int(time_diff.total_seconds() / 60)}m ago"
        elif time_diff < timedelta(hours=24):
            time_ago = f"{int(time_diff.total_seconds() / 3600)}h ago"
        else:
            time_ago = f"{int(time_diff.total_seconds() / 86400)}d ago"
        
        return {
            'id': self.id,
            'title': self.alert_title,
            'subtitle': self.alert_subtitle,
            'description': self.alert_description,
            'risk_level': self.risk_level,
            'risk_category': self.risk_category,
            'fraud_score': self.fraud_score,
            'time_ago': time_ago,
            'job_url': self.job_url,
            'is_read': self.is_read,
            'created_at': self.created_at.isoformat()
        }


class User_Alert_Preferences(db.Model):
    """Track user's job viewing history"""
    __tablename__ = 'user_alert_preferences'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id', ondelete='CASCADE'), nullable=False, unique=True)
    viewed_job_ids = db.Column(db.Text, nullable=True)
    preferred_categories = db.Column(db.Text, nullable=True)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('alert_preferences', uselist=False))