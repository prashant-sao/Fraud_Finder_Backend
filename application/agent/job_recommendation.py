import logging
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import quote_plus, urljoin
from datetime import datetime, timedelta
import hashlib
import json

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Import database and models
try:
    from application.database import db
    from application.models import User
except Exception:
    db = None
    User = None
    logger.warning("Database models not available")


class SimpleFraudDetector:
    """Built-in fraud detector if the main one isn't available"""
    
    def __init__(self):
        self.salary_red_flags = [
            'guaranteed income', 'unlimited earning', 'earn thousands weekly',
            'work from home earn', 'no experience high pay', 'quick money',
            'earn $', 'make money fast', 'financial freedom', 'get rich'
        ]
        
        self.description_red_flags = [
            'act now', 'limited time', 'urgent', 'immediate start',
            'no experience necessary', 'easy money', 'risk free',
            'investment required', 'pay to apply', 'processing fee',
            'training fee', 'starter kit', 'send money', 'wire transfer',
            'upfront payment', 'registration fee'
        ]
    
    def analyze(self, job_title, job_company, job_description, job_url):
        """Analyze job and return fraud score"""
        if '<' in job_description and '>' in job_description:
            soup = BeautifulSoup(job_description, 'html.parser')
            job_description = soup.get_text()
        
        content = f"{job_title} {job_company} {job_description}".lower()
        fraud_score = 0
        red_flags = []
        
        if len(job_description.split()) < 30:
            fraud_score += 15
            red_flags.append('vague_description')
        
        for flag in self.salary_red_flags:
            if flag in content:
                fraud_score += 20
                red_flags.append('unrealistic_salary')
                break
        
        suspicious_count = sum(1 for flag in self.description_red_flags if flag in content)
        if suspicious_count >= 2:
            fraud_score += 20
            red_flags.append('suspicious_keywords')
        elif suspicious_count == 1:
            fraud_score += 10
            red_flags.append('minor_suspicious_keywords')
        
        if not job_company or job_company == 'N/A' or len(job_company) < 3:
            fraud_score += 15
            red_flags.append('no_company_info')
        
        if re.search(r'@(gmail|yahoo|hotmail|outlook)\.com', content):
            fraud_score += 15
            red_flags.append('personal_email')
        
        domain = re.search(r'https?://(?:www\.)?([^/]+)', job_url)
        if domain:
            domain = domain.group(1).lower()
            trusted_domains = ['indeed.com', 'linkedin.com', 'glassdoor.com', 'remoteok.com', 'weworkremotely.com']
            if not any(trusted in domain for trusted in trusted_domains):
                fraud_score += 10
                red_flags.append('unverified_source')
        
        personal_info_keywords = ['social security', 'ssn', 'bank account', 'credit card', 'passport']
        if any(keyword in content for keyword in personal_info_keywords):
            fraud_score += 25
            red_flags.append('requests_personal_info')
        
        if fraud_score >= 60:
            risk_level = "High Risk"
        elif fraud_score >= 30:
            risk_level = "Medium Risk"
        else:
            risk_level = "Low Risk"
        
        return {
            'fraud_score': min(fraud_score, 100),
            'risk_level': risk_level,
            'red_flags': red_flags,
            'is_safe': fraud_score < 30
        }


try:
    from application.agent.risk_score import JobFraudDetector
    fraud_detector = JobFraudDetector()
    logger.info("✅ Using JobFraudDetector from risk_score.py")
except Exception as e:
    fraud_detector = SimpleFraudDetector()
    logger.warning(f"⚠️ Using SimpleFraudDetector (fallback): {e}")


class MLJobRecommender:
    """Personalized job recommender with simplified frontend response format."""

    def __init__(self):
        pass

    def get_recommendations(self, limit=10, search_query=None, user_id=None):
        """
        Get personalized job recommendations with fraud analysis.
        Returns simplified format: [{ title, company, link, description, fraud_score }, ...]
        """
        if user_id and User and db:
            jobs = self._get_personalized_recommendations(user_id, limit)
        else:
            jobs = self._get_generic_recommendations(limit, search_query)
        
        # Convert to frontend-friendly format
        return self._format_for_frontend(jobs)
    
    def _get_personalized_recommendations(self, user_id, limit=10):
        """Get personalized recommendations based on user profile"""
        try:
            from application.models import User_Job_Alerts, User_Alert_Preferences
            
            user = User.query.get(user_id)
            if not user:
                logger.error(f"User {user_id} not found")
                return []
            
            preferences = User_Alert_Preferences.query.filter_by(user_id=user_id).first()
            if not preferences:
                preferences = User_Alert_Preferences(
                    user_id=user_id,
                    viewed_job_ids=json.dumps([])
                )
                db.session.add(preferences)
                db.session.commit()
            
            viewed_jobs = json.loads(preferences.viewed_job_ids) if preferences.viewed_job_ids else []
            search_terms = self._get_user_search_terms(user)
            
            all_jobs = []
            for query in search_terms:
                try:
                    indeed_jobs = self._search_indeed(query, "Remote", limit=5)
                    all_jobs.extend(indeed_jobs)
                except Exception as e:
                    logger.error(f"Indeed search failed for '{query}': {e}")
                
                try:
                    remote_jobs = self._search_remote_ok(query, limit=5)
                    all_jobs.extend(remote_jobs)
                except Exception as e:
                    logger.error(f"RemoteOK search failed for '{query}': {e}")
                
                if len(all_jobs) >= limit * 3:
                    break
            
            if len(all_jobs) == 0:
                logger.warning(f"No jobs found for user {user_id}, fetching generic recent jobs")
                try:
                    generic_jobs = self._search_remote_ok("", limit=limit * 2)
                    all_jobs.extend(generic_jobs)
                except Exception as e:
                    logger.error(f"Fallback job fetch failed: {e}")
            
            seen_urls = set(viewed_jobs)
            unique_jobs = []
            for job in all_jobs:
                job_hash = self._hash_job(job['url'], job['title'])
                if job_hash not in seen_urls:
                    seen_urls.add(job_hash)
                    unique_jobs.append(job)
            
            if len(unique_jobs) == 0:
                logger.error(f"❌ No jobs available for user {user_id} after all attempts")
                return []
            
            logger.info(f"🔍 Analyzing {len(unique_jobs)} unique jobs for fraud (User {user_id})...")
            
            # Run fraud analysis on all jobs
            for job in unique_jobs:
                fraud_analysis = self._run_fraud_detection(
                    job.get("title", ""),
                    job.get("company", ""),
                    job.get("description", ""),
                    job.get("url", "")
                )
                job["fraud_score"] = fraud_analysis.get("fraud_score", 0)
                job["is_safe"] = fraud_analysis.get("is_safe", True)
            
            # Get mixed recommendations
            mixed_jobs = self._get_mixed_recommendations(unique_jobs, limit)
            
            # Update viewed jobs
            new_viewed = viewed_jobs + [self._hash_job(j['url'], j['title']) for j in mixed_jobs]
            preferences.viewed_job_ids = json.dumps(new_viewed[-200:])
            preferences.last_updated = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"✅ Returning {len(mixed_jobs)} job recommendations for user {user_id}")
            return mixed_jobs
            
        except Exception as e:
            logger.error(f"Personalized recommendations error: {e}")
            if db:
                db.session.rollback()
            return self._get_generic_recommendations(limit, None)
    
    def _get_generic_recommendations(self, limit=10, search_query=None):
        """Get generic recommendations (fallback when no user_id)"""
        if search_query:
            search_terms = [search_query]
        else:
            search_terms = [
                "software engineer", "data analyst", "developer",
                "designer", "product manager"
            ]
        
        all_jobs = []
        for query in search_terms[:3]:
            try:
                indeed_jobs = self._search_indeed(query, "Remote", limit=5)
                all_jobs.extend(indeed_jobs)
            except Exception as e:
                logger.error(f"Indeed search failed: {e}")
            
            try:
                remote_jobs = self._search_remote_ok(query, limit=5)
                all_jobs.extend(remote_jobs)
            except Exception as e:
                logger.error(f"RemoteOK search failed: {e}")
            
            if len(all_jobs) >= limit * 2:
                break
        
        if len(all_jobs) == 0:
            logger.warning("No jobs found with search terms, fetching recent jobs")
            try:
                all_jobs = self._search_remote_ok("", limit=limit * 2)
            except Exception as e:
                logger.error(f"Fallback fetch failed: {e}")
        
        # Remove duplicates
        seen_urls = set()
        unique_jobs = []
        for job in all_jobs:
            if job['url'] not in seen_urls:
                seen_urls.add(job['url'])
                unique_jobs.append(job)
        
        logger.info(f"🔍 Analyzing {len(unique_jobs)} jobs for fraud...")
        
        # Run fraud analysis
        for job in unique_jobs:
            try:
                fraud_analysis = self._run_fraud_detection(
                    job.get("title", ""),
                    job.get("company", ""),
                    job.get("description", ""),
                    job.get("url", "")
                )
                job["fraud_score"] = fraud_analysis.get("fraud_score", 0)
                job["is_safe"] = fraud_analysis.get("is_safe", True)
            except Exception as e:
                logger.error(f"Fraud analysis failed for {job.get('title', 'Unknown')}: {e}")
                job["fraud_score"] = 0
                job["is_safe"] = True
        
        return self._get_mixed_recommendations(unique_jobs, limit)
    
    def _run_fraud_detection(self, title, company, description, url):
        """Run fraud detection with proper method detection"""
        try:
            if hasattr(fraud_detector, 'quick_analyze'):
                return fraud_detector.quick_analyze(title, company, description, url)
            elif hasattr(fraud_detector, 'analyze'):
                return fraud_detector.analyze(title, company, description, url)
            elif hasattr(fraud_detector, 'analyze_job_posting'):
                result = fraud_detector.analyze_job_posting(description, url)
                if isinstance(result, dict) and 'fraud_score' in result:
                    return result
            
            logger.warning("No suitable fraud detection method found, using fallback")
            fallback = SimpleFraudDetector()
            return fallback.analyze(title, company, description, url)
            
        except Exception as e:
            logger.error(f"Fraud detection error: {e}")
            return {
                'fraud_score': 0,
                'risk_level': 'Unknown',
                'red_flags': [],
                'is_safe': True
            }
    
    def _get_user_search_terms(self, user):
        """Generate search terms based on user profile"""
        search_terms = []
        
        keyword_mapping = {
            'technology': ['software engineer', 'developer', 'tech support'],
            'student': ['internship', 'entry level', 'junior developer'],
            'business': ['business analyst', 'consultant', 'account manager'],
            'marketing': ['marketing manager', 'content writer', 'social media'],
            'design': ['designer', 'UI/UX', 'graphic designer'],
            'sales': ['sales representative', 'account executive'],
            'engineering': ['software engineer', 'mechanical engineer'],
            'finance': ['financial analyst', 'accountant'],
            'data': ['data analyst', 'data scientist', 'data engineer'],
            'management': ['project manager', 'product manager'],
        }
        
        if user.fields_of_interest:
            interests = [i.strip().lower() for i in user.fields_of_interest.split(',')]
            for interest in interests[:3]:
                if interest in keyword_mapping:
                    search_terms.extend(keyword_mapping[interest][:2])
                else:
                    search_terms.append(interest)
        
        if user.qualifications:
            qual = user.qualifications.strip().lower()
            if qual in keyword_mapping:
                search_terms.extend(keyword_mapping[qual][:2])
            else:
                search_terms.append(qual)
        
        seen = set()
        unique_terms = []
        for term in search_terms:
            if term not in seen:
                seen.add(term)
                unique_terms.append(term)
        
        if not unique_terms or len(unique_terms) < 2:
            unique_terms = ['software engineer', 'data analyst', 'developer', 'designer']
        
        logger.info(f"🔍 Search terms for user: {unique_terms}")
        return unique_terms[:5]
    
    def _hash_job(self, url, title):
        """Create unique hash for job tracking"""
        content = f"{url}{title}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _get_mixed_recommendations(self, jobs, limit):
        """Return mixed recommendations: 60% safe, 40% risky"""
        safe_jobs = [j for j in jobs if j.get("is_safe", False)]
        risky_jobs = [j for j in jobs if not j.get("is_safe", False)]
        
        safe_count = int(limit * 0.6)
        risky_count = limit - safe_count
        
        logger.info(f"🔀 Mixed mode: {len(safe_jobs)} safe jobs, {len(risky_jobs)} risky jobs available")
        logger.info(f"📦 Selecting: {safe_count} safe + {risky_count} risky = {limit} total")
        
        mixed = safe_jobs[:safe_count] + risky_jobs[:risky_count]
        
        if len(mixed) < limit:
            remaining = limit - len(mixed)
            if len(safe_jobs) > safe_count:
                mixed.extend(safe_jobs[safe_count:safe_count + remaining])
            elif len(risky_jobs) > risky_count:
                mixed.extend(risky_jobs[risky_count:risky_count + remaining])
        
        return mixed[:limit]
    
    def _format_for_frontend(self, jobs):
        """
        Format jobs for frontend consumption.
        Returns simplified list: [{ title, company, link, description, fraud_score }, ...]
        """
        formatted_jobs = []
        for job in jobs:
            formatted_jobs.append({
                "title": job.get("title", "N/A"),
                "company": job.get("company", "N/A"),
                "link": job.get("url", ""),
                "description": job.get("description", "")[:300],  # Truncate to 300 chars
                "fraud_score": job.get("fraud_score", 0)
            })
        return formatted_jobs
    
    def _search_indeed(self, query, location, limit=5):
        """Scrape basic job info from Indeed"""
        jobs = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "en-US,en;q=0.5",
        }
        try:
            url = f"https://www.indeed.com/jobs?q={quote_plus(query)}&l={quote_plus(location)}"
            resp = requests.get(url, headers=headers, timeout=15)
            
            if resp.status_code == 403:
                logger.warning(f"Indeed blocked request for '{query}'")
                return jobs
            
            resp.raise_for_status()
            soup = BeautifulSoup(resp.content, "html.parser")
            job_cards = soup.find_all("div", class_=re.compile("job_seen_beacon|jobsearch-SerpJobCard"))
            
            for card in job_cards[:limit]:
                try:
                    title_elem = card.find("h2", class_="jobTitle")
                    company_elem = card.find("span", class_="companyName")
                    snippet_elem = card.find("div", class_="job-snippet")
                    
                    if title_elem and company_elem:
                        title = title_elem.get_text(strip=True)
                        company = company_elem.get_text(strip=True)
                        description = snippet_elem.get_text(strip=True) if snippet_elem else ""
                        link_elem = card.find("a", class_="jcs-JobTitle")
                        job_url = urljoin("https://www.indeed.com", link_elem["href"]) if link_elem and link_elem.get("href") else url
                        
                        jobs.append({
                            "title": title,
                            "company": company,
                            "description": description,
                            "url": job_url,
                            "source": "Indeed"
                        })
                except Exception:
                    continue
                    
            logger.info(f"✅ Indeed: Found {len(jobs)} jobs for '{query}'")
        except Exception as e:
            logger.error(f"Indeed search error: {e}")
        return jobs
    
    def _search_remote_ok(self, query, limit=5):
        """Use RemoteOK public API"""
        jobs = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json"
        }
        try:
            url = "https://remoteok.com/api"
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            
            query_lower = query.lower().strip()
            query_keywords = query_lower.split()
            
            filtered = []
            for job in data[1:]:
                if not isinstance(job, dict):
                    continue
                
                position = job.get("position", "").lower()
                company = job.get("company", "").lower()
                description = job.get("description", "").lower()
                tags = " ".join(job.get("tags", [])).lower()
                
                searchable_text = f"{position} {company} {description} {tags}"
                
                matches = False
                if query_lower == "":
                    matches = True
                elif query_lower in searchable_text:
                    matches = True
                else:
                    for keyword in query_keywords:
                        if len(keyword) > 2 and keyword in searchable_text:
                            matches = True
                            break
                
                if matches:
                    filtered.append(job)
            
            if not filtered and query_lower != "":
                logger.warning(f"No exact matches for '{query}', returning recent jobs")
                filtered = [job for job in data[1:51] if isinstance(job, dict)]
            
            for job in filtered[:limit]:
                description = job.get("description", "") or ""
                
                jobs.append({
                    "title": job.get("position", "N/A"),
                    "company": job.get("company", "N/A"),
                    "description": description,
                    "url": job.get("url", "https://remoteok.com"),
                    "source": "Remote OK"
                })
            
            logger.info(f"✅ RemoteOK: Found {len(jobs)} jobs for '{query}'")
        except Exception as e:
            logger.error(f"Remote OK search error: {e}")
        return jobs


# Global instance
ml_recommender = MLJobRecommender()