"""
Pydantic Schemas for API Requests and Responses.
"""

from pydantic import BaseModel
from typing import Optional, List

class LoginRequest(BaseModel):
    username: str
    password: str

class OTPVerifyRequest(BaseModel):
    username: str
    otp_code: str

class QuestionPaperUploadRequest(BaseModel):
    paper_code: str
    title: str
    subject: str
    content: str
    scheduled_release_time: str # ISO String

class ApprovalRequest(BaseModel):
    paper_id: int
    action: str # "APPROVE" or "REJECT"
    scheduled_release_time: Optional[str] = None

class DecryptRequest(BaseModel):
    paper_code: str

class ReleaseTimeOverrideRequest(BaseModel):
    paper_code: str
    new_release_time: str # ISO string or "NOW"
