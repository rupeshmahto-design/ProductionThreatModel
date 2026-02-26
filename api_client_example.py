"""
Example Python client for the Threat Modeling API
Shows how to use the API programmatically
"""

import requests
from typing import Dict, List, Optional, Any
from datetime import datetime


class ThreatModelingClient:
    """Client for the AI Threat Modeling API"""
    
    def __init__(self, base_url: str, api_key: str):
        """
        Initialize the client
        
        Args:
            base_url: API base URL (e.g., http://localhost:8000)
            api_key: Your API key (starts with tm_)
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        })
    
    def health_check(self) -> Dict[str, Any]:
        """Check API health"""
        response = self.session.get(f"{self.base_url}/api/health")
        response.raise_for_status()
        return response.json()
    
    def create_threat_assessment(
        self,
        project_name: str,
        system_description: str,
        framework: str,
        risk_type: Optional[str] = None,
        company_name: Optional[str] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a new threat assessment
        
        Args:
            project_name: Name of the project
            system_description: Description of the system to analyze
            framework: Threat modeling framework (STRIDE, MITRE ATT&CK, PASTA, etc.)
            risk_type: Type of risk (Agentic AI, Model Risk, Data Security, etc.)
            company_name: Company name for branding
            additional_context: Extra context for analysis
        
        Returns:
            Dict containing assessment details including the full report
        """
        payload = {
            "project_name": project_name,
            "system_description": system_description,
            "framework": framework
        }
        
        if risk_type:
            payload["risk_type"] = risk_type
        if company_name:
            payload["company_name"] = company_name
        if additional_context:
            payload["additional_context"] = additional_context
        
        response = self.session.post(
            f"{self.base_url}/api/v1/threat-modeling",
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    def get_threat_assessment(self, assessment_id: int) -> Dict[str, Any]:
        """
        Get a specific threat assessment by ID
        
        Args:
            assessment_id: The assessment ID
        
        Returns:
            Dict containing assessment details
        """
        response = self.session.get(
            f"{self.base_url}/api/v1/threat-modeling/{assessment_id}"
        )
        response.raise_for_status()
        return response.json()
    
    def list_threat_assessments(
        self,
        skip: int = 0,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        List threat assessments for your organization
        
        Args:
            skip: Number of records to skip (pagination)
            limit: Maximum number of records to return
        
        Returns:
            List of assessment dictionaries
        """
        response = self.session.get(
            f"{self.base_url}/api/v1/threat-modeling",
            params={'skip': skip, 'limit': limit}
        )
        response.raise_for_status()
        return response.json()
    
    def list_users(self) -> List[Dict[str, Any]]:
        """
        List all users in your organization (admin only)
        
        Returns:
            List of user dictionaries
        """
        response = self.session.get(f"{self.base_url}/api/v1/admin/users")
        response.raise_for_status()
        return response.json()
    
    def get_audit_logs(
        self,
        skip: int = 0,
        limit: int = 100,
        action: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get audit logs for your organization (admin only)
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records
            action: Filter by specific action (e.g., 'user.login')
        
        Returns:
            List of audit log entries
        """
        params = {'skip': skip, 'limit': limit}
        if action:
            params['action'] = action
        
        response = self.session.get(
            f"{self.base_url}/api/v1/admin/audit-logs",
            params=params
        )
        response.raise_for_status()
        return response.json()
    
    def get_usage_stats(self) -> Dict[str, Any]:
        """
        Get usage statistics for your organization (admin only)
        
        Returns:
            Dict containing usage metrics
        """
        response = self.session.get(f"{self.base_url}/api/v1/admin/usage-stats")
        response.raise_for_status()
        return response.json()


# Example usage
def main():
    """Example usage of the client"""
    
    # Initialize client
    client = ThreatModelingClient(
        base_url="http://localhost:8000",
        api_key="tm_your_api_key_here"  # Replace with your actual API key
    )
    
    # Health check
    print("Checking API health...")
    health = client.health_check()
    print(f"✅ API is healthy: {health}")
    print()
    
    # Create a threat assessment
    print("Creating threat assessment...")
    assessment = client.create_threat_assessment(
        project_name="E-Commerce Platform Security Review",
        system_description="""
        Web application with the following components:
        - React frontend
        - Node.js backend API
        - PostgreSQL database
        - Redis cache
        - AWS S3 for file storage
        - Stripe payment integration
        - User authentication with JWT
        - Admin panel for order management
        """,
        framework="STRIDE",
        risk_type="Application Security",
        company_name="Acme Corporation"
    )
    
    assessment_id = assessment['assessment_id']
    print(f"✅ Created assessment #{assessment_id}")
    print(f"   Project: {assessment['project_name']}")
    print(f"   Framework: {assessment['framework']}")
    print(f"   Status: {assessment['status']}")
    print()
    
    # Print first 500 chars of report
    report = assessment['report']
    print("Report preview:")
    print("=" * 60)
    print(report[:500] + "...")
    print("=" * 60)
    print()
    
    # Get the assessment by ID
    print(f"Retrieving assessment #{assessment_id}...")
    retrieved = client.get_threat_assessment(assessment_id)
    print(f"✅ Retrieved: {retrieved['project_name']}")
    print()
    
    # List all assessments
    print("Listing recent assessments...")
    assessments = client.list_threat_assessments(limit=5)
    print(f"✅ Found {len(assessments)} assessments:")
    for a in assessments:
        print(f"   - #{a['assessment_id']}: {a['project_name']} ({a['framework']})")
    print()
    
    # Admin operations (if you have admin access)
    try:
        print("Getting usage statistics (admin only)...")
        stats = client.get_usage_stats()
        print(f"✅ Usage stats:")
        print(f"   Total assessments: {stats['total_assessments']}")
        print(f"   Total API calls: {stats['total_api_calls']}")
        print(f"   Total users: {stats['total_users']}")
        print(f"   Active users: {stats['active_users']}")
        print()
        
        print("Getting recent audit logs (admin only)...")
        logs = client.get_audit_logs(limit=5)
        print(f"✅ Found {len(logs)} audit log entries:")
        for log in logs:
            print(f"   - {log['timestamp']}: {log['action']} by {log['user_email']}")
        print()
        
    except requests.HTTPError as e:
        if e.response.status_code == 403:
            print("⚠️  Skipping admin operations (insufficient permissions)")
            print()
        else:
            raise


if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        print(f"\n❌ API Error: {e}")
        print(f"   Response: {e.response.text}")
    except Exception as e:
        print(f"\n❌ Error: {e}")
