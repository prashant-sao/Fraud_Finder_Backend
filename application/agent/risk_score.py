from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import json
import time
from datetime import datetime

# Import database models
from application.models import (
    db, Job_Posting, Analysis_Results, Fraud_Indicators,
    Company_Verification, Community_Reports
)


class JobFraudDetector:
    def __init__(self):
        # Red flag keywords
        self.salary_red_flags = [
            'guaranteed income', 'unlimited earning', 'earn thousands weekly',
            'work from home earn', 'no experience high pay', 'quick money'
        ]
        
        self.description_red_flags = [
            'act now', 'limited time', 'urgent', 'immediate start',
            'no experience necessary', 'easy money', 'risk free',
            'work from home', 'be your own boss', 'financial freedom',
            'investment required', 'pay to apply', 'processing fee',
            'training fee', 'starter kit'
        ]
        
        self.contact_red_flags = [
            'personal email', 'gmail', 'yahoo', 'hotmail', 'whatsapp only',
            'telegram only', 'no phone', 'contact via social media'
        ]
        
        self.linkedin_patterns = [
            r'linkedin\.com/company/[\w-]+',
            r'linkedin\.com/in/[\w-]+',
            r'www\.linkedin\.com'
        ]
        
        self.website_patterns = [
            r'https?://(?:www\.)?[\w-]+\.(?:com|org|net|io|co)',
            r'www\.[\w-]+\.(?:com|org|net|io|co)'
        ]

    def fetch_job_posting(self, url):
        """Fetch and parse job posting from URL"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract text content
            text_content = soup.get_text(separator=' ', strip=True)
            
            return {
                'success': True,
                'content': text_content,
                'title': soup.find('title').get_text() if soup.find('title') else 'Unknown',
                'html': str(soup)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def analyze_job_posting(self, content, url, user_id=None, save_to_db=True):
        """Analyze job posting for fraud indicators and save to database"""
        content_lower = content.lower()
        fraud_score = 0
        red_flags = {}
        details = {}

        # Extract basic job info
        company_name = self._extract_company_name(content)
        job_title = self._extract_job_title(content)

        # Check 1: Vague Job Description (15 points)
        vague_desc = self._check_vague_description(content)
        red_flags['vague_description'] = vague_desc
        if vague_desc:
            fraud_score += 15
            details['vague_description'] = True

        # Check 2: Unrealistic Salary/Benefits (20 points)
        salary_check = self._check_unrealistic_salary(content_lower)
        red_flags['unrealistic_salary'] = salary_check['is_suspicious']
        if salary_check['is_suspicious']:
            fraud_score += 20
            details['unrealistic_salary'] = salary_check['reasons']

        # Check 3: No Company Information (15 points)
        company_check = self._check_company_info(content_lower, url)
        red_flags['no_company_info'] = company_check['missing']
        if company_check['missing']:
            fraud_score += 15
            details['no_company_info'] = True

        # Check 4: Request for Personal Details (15 points)
        personal_details = self._check_personal_details_request(content_lower)
        red_flags['requests_personal_details'] = personal_details
        if personal_details:
            fraud_score += 15
            details['requests_personal_details'] = True

        # Check 5: Poor Grammar/Spelling (10 points)
        grammar_score = self._check_grammar(content)
        poor_grammar = grammar_score > 5
        red_flags['poor_grammar'] = poor_grammar
        if poor_grammar:
            fraud_score += 10
            details['poor_grammar'] = grammar_score

        # Check 6: Suspicious Contact Methods (10 points)
        contact_check = self._check_contact_methods(content_lower)
        red_flags['suspicious_contact'] = contact_check['is_suspicious']
        if contact_check['is_suspicious']:
            fraud_score += 10
            details['suspicious_contact'] = contact_check['reasons']
        
        # Check 7: No LinkedIn Presence (10 points)
        linkedin_check = self._check_linkedin_presence(content, content_lower)
        red_flags['no_linkedin'] = not linkedin_check['has_linkedin']
        if not linkedin_check['has_linkedin']:
            fraud_score += 10
            details['no_linkedin'] = True
        else:
            details['linkedin_found'] = linkedin_check['linkedin_url']
        
        # Check 8: No Company Website (15 points)
        website_check = self._check_company_website(content, content_lower, url)
        red_flags['no_company_website'] = not website_check['has_website']
        if not website_check['has_website']:
            fraud_score += 15
            details['no_company_website'] = True
        else:
            details['company_website'] = website_check['website_url']
            details['website_status'] = website_check['status']

        # Cap at 100
        fraud_score = min(fraud_score, 100)

        # Determine verdict
        if fraud_score >= 80:
            verdict = "Likely Fraudulent"
            risk_level = "High Risk"
        elif fraud_score >= 40:
            verdict = "Possibly Fraudulent"
            risk_level = "Medium Risk"
        else:
            verdict = "Appears Legitimate"
            risk_level = "Low Risk"

        analysis_result = {
            'fraud_score': fraud_score,
            'verdict': verdict,
            'risk_level': risk_level,
            'red_flags': red_flags,
            'details': details,
            'company_name': company_name,
            'job_title': job_title
        }

        # Save to database if requested
        if save_to_db:
            try:
                db_result = self._save_to_database(
                    url=url,
                    content=content,
                    analysis_result=analysis_result,
                    user_id=user_id,
                    website_check=website_check,
                    linkedin_check=linkedin_check
                )
                analysis_result['job_id'] = db_result['job_id']
                analysis_result['analysis_id'] = db_result['analysis_id']
            except Exception as e:
                print(f"Error saving to database: {str(e)}")
                # Continue without database save
                pass

        return analysis_result

    def _extract_company_name(self, content):
        """Extract company name from content"""
        # Look for common patterns
        patterns = [
            r'Company:\s*([^\n]+)',
            r'Organization:\s*([^\n]+)',
            r'Employer:\s*([^\n]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return "Unknown Company"

    def _extract_job_title(self, content):
        """Extract job title from content"""
        # Look for common patterns
        patterns = [
            r'Job Title:\s*([^\n]+)',
            r'Position:\s*([^\n]+)',
            r'Role:\s*([^\n]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        # Fallback: use first line or first 100 chars
        lines = content.split('\n')
        if lines:
            return lines[0][:100].strip()
        
        return "Unknown Position"

    def _save_to_database(self, url, content, analysis_result, user_id, website_check, linkedin_check):
        """Save analysis results to database"""
        try:
            # Create or get Job_Posting
            job_posting = Job_Posting.query.filter_by(url=url).first()
            
            if not job_posting:
                job_posting = Job_Posting(
                    url=url,
                    company_name=analysis_result['company_name'],
                    job_title=analysis_result['job_title'],
                    job_description=content[:5000],  # Limit length
                    submitted_by=user_id,
                    submitted_at=datetime.utcnow()
                )
                db.session.add(job_posting)
                db.session.flush()  # Get the job_id
            
            # Create Analysis_Results
            analysis_record = Analysis_Results(
                job_id=job_posting.job_id,
                risk_score=analysis_result['fraud_score'],
                verdict=analysis_result['verdict'],
                risk_level=analysis_result['risk_level'],
                summary_labels=json.dumps(analysis_result['red_flags']),
                analyzed_at=datetime.utcnow()
            )
            db.session.add(analysis_record)
            db.session.flush()  # Get the analysis_id
            
            # Create Fraud_Indicators for each red flag
            for flag_type, flag_value in analysis_result['red_flags'].items():
                if flag_value:  # Only save if the flag is True
                    severity = self._determine_severity(flag_type, analysis_result['fraud_score'])
                    
                    indicator = Fraud_Indicators(
                        analysis_id=analysis_record.analysis_id,
                        indicator_type=flag_type,
                        description=json.dumps(analysis_result['details'].get(flag_type, {})),
                        severity_level=severity,
                        detected_at=datetime.utcnow(),
                        confidence_score=1.0
                    )
                    db.session.add(indicator)
            
            # Update or create Company_Verification
            company = Company_Verification.query.filter_by(
                company_name=analysis_result['company_name']
            ).first()
            
            if not company:
                company = Company_Verification(
                    company_name=analysis_result['company_name'],
                    linkedin_url=linkedin_check.get('linkedin_url'),
                    website_url=website_check.get('website_url'),
                    social_presence=linkedin_check.get('has_linkedin', False),
                    website_accessible=website_check.get('accessible', False),
                    last_checked=datetime.utcnow(),
                    total_jobs_posted=1
                )
                db.session.add(company)
            else:
                company.total_jobs_posted += 1
                company.last_checked = datetime.utcnow()
                if analysis_result['fraud_score'] >= 70:
                    company.fraud_jobs_count += 1
            
            # Commit all changes
            db.session.commit()
            
            return {
                'job_id': job_posting.job_id,
                'analysis_id': analysis_record.analysis_id
            }
            
        except Exception as e:
            db.session.rollback()
            raise e

    def _determine_severity(self, flag_type, fraud_score):
        """Determine severity level based on flag type and overall score"""
        high_severity_flags = ['requests_personal_details', 'unrealistic_salary']
        medium_severity_flags = ['suspicious_contact', 'no_company_info', 'no_company_website']
        
        if flag_type in high_severity_flags or fraud_score >= 70:
            return 'High'
        elif flag_type in medium_severity_flags or fraud_score >= 40:
            return 'Medium'
        else:
            return 'Low'

    def _check_vague_description(self, content):
        """Check if job description is too vague"""
        # Very short description
        if len(content.split()) < 50:
            return True
        
        # Missing key elements
        has_responsibilities = any(word in content.lower() for word in 
                                  ['responsibilities', 'duties', 'role', 'tasks'])
        has_requirements = any(word in content.lower() for word in 
                              ['requirements', 'qualifications', 'skills', 'experience'])
        
        return not (has_responsibilities and has_requirements)

    def _check_unrealistic_salary(self, content):
        """Check for unrealistic salary promises"""
        reasons = []
        
        for flag in self.salary_red_flags:
            if flag in content:
                reasons.append(flag)
        
        # Check for very high amounts without context
        salary_patterns = [
            r'\$\d{4,},?\d*\+?\s*(per|a|/)?\s*(day|week)',
            r'earn\s+\$\d{4,}'
        ]
        
        for pattern in salary_patterns:
            if re.search(pattern, content):
                reasons.append('suspiciously_high_earnings')
        
        return {
            'is_suspicious': len(reasons) > 0,
            'reasons': reasons
        }
    
    def _check_linkedin_presence(self, content, content_lower):
        """Check for LinkedIn company or recruiter profile"""
        # Look for LinkedIn URLs
        linkedin_urls = []
        
        for pattern in self.linkedin_patterns:
            matches = re.findall(pattern, content_lower)
            linkedin_urls.extend(matches)
        
        # Also check for mentions of LinkedIn
        has_linkedin_mention = 'linkedin' in content_lower
        
        return {
            'has_linkedin': len(linkedin_urls) > 0 or has_linkedin_mention,
            'linkedin_url': linkedin_urls[0] if linkedin_urls else None,
            'mention_only': has_linkedin_mention and len(linkedin_urls) == 0
        }
    
    def _check_company_website(self, content, content_lower, job_url):
        """Check for company website and verify if it's accessible"""
        # Extract potential website URLs
        website_urls = []
        
        for pattern in self.website_patterns:
            matches = re.findall(pattern, content_lower)
            # Filter out the job posting URL itself and common third-party sites
            filtered = [url for url in matches if url not in job_url and 
                       not any(excluded in url for excluded in 
                              ['indeed', 'linkedin', 'glassdoor', 'monster', 'naukri'])]
            website_urls.extend(filtered)
        
        if not website_urls:
            return {
                'has_website': False,
                'website_url': None,
                'status': 'not_found'
            }
        
        # Try to verify the first website
        website_url = website_urls[0]
        if not website_url.startswith('http'):
            website_url = 'https://' + website_url
        
        verification = self._verify_website(website_url)
        
        return {
            'has_website': True,
            'website_url': website_url,
            'status': verification['status'],
            'accessible': verification['accessible']
        }
    
    def _verify_website(self, url):
        """Verify if a website is accessible"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
            
            if response.status_code == 200:
                return {
                    'accessible': True,
                    'status': 'active'
                }
            else:
                return {
                    'accessible': False,
                    'status': f'error_{response.status_code}'
                }
        except requests.exceptions.Timeout:
            return {
                'accessible': False,
                'status': 'timeout'
            }
        except requests.exceptions.ConnectionError:
            return {
                'accessible': False,
                'status': 'connection_error'
            }
        except Exception as e:
            return {
                'accessible': False,
                'status': 'unknown_error'
            }

    def _check_company_info(self, content, url):
        """Check if company information is missing or suspicious"""
        domain = urlparse(url).netloc
        
        # Check for company name
        has_company = any(word in content for word in 
                         ['company', 'corporation', 'inc', 'llc', 'ltd'])
        
        # Check for company website
        has_website = 'website' in content or 'www.' in content
        
        # Check for physical address
        has_address = any(word in content for word in 
                         ['address', 'location', 'office', 'headquarters'])
        
        missing_count = sum([not has_company, not has_website, not has_address])
        
        return {
            'missing': missing_count >= 2,
            'missing_count': missing_count
        }

    def _check_personal_details_request(self, content):
        """Check for suspicious requests for personal information"""
        suspicious_requests = [
            'social security', 'ssn', 'bank account', 'credit card',
            'driver license', 'passport number', 'send money',
            'wire transfer', 'payment required'
        ]
        
        return any(req in content for req in suspicious_requests)

    def _check_grammar(self, content):
        """Basic grammar check - count obvious errors"""
        errors = 0
        
        # Multiple exclamation marks
        errors += len(re.findall(r'!{2,}', content))
        
        # All caps words (excluding acronyms)
        all_caps = re.findall(r'\b[A-Z]{4,}\b', content)
        errors += len([w for w in all_caps if len(w) > 5])
        
        # Multiple spaces
        errors += len(re.findall(r'\s{3,}', content))
        
        return errors

    def _check_contact_methods(self, content):
        """Check for suspicious contact methods"""
        reasons = []
        
        # Personal email domains
        if re.search(r'@(gmail|yahoo|hotmail|outlook)\.com', content):
            reasons.append('personal_email')
        
        # Only social media contact
        social_media = ['whatsapp', 'telegram', 'facebook', 'instagram']
        if any(platform in content for platform in social_media):
            if 'email' not in content and 'phone' not in content:
                reasons.append('social_media_only')
        
        return {
            'is_suspicious': len(reasons) > 0,
            'reasons': reasons
        }