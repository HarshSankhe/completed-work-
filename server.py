from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import jwt
from passlib.context import CryptContext
import hashlib

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security configuration
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-here')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Create the main app
app = FastAPI(title="HR Management System API")
api_router = APIRouter(prefix="/api")

# Pydantic Models
class UserBase(BaseModel):
    email: EmailStr
    full_name: str
    employee_id: str
    department: str
    role: str = "employee"  # employee or hr_admin
    phone: Optional[str] = None
    hire_date: Optional[datetime] = None
    is_active: bool = True

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str
    wifi_ssid: Optional[str] = None
    ip_address: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User

class AttendanceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    employee_id: str
    date: str  # YYYY-MM-DD format
    punch_in: Optional[datetime] = None
    punch_out: Optional[datetime] = None
    wifi_disconnections: int = 0
    status: str = "present"  # present, half_day, absent
    location: Optional[Dict[str, Any]] = None
    wifi_info: Optional[Dict[str, str]] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AttendancePunch(BaseModel):
    punch_type: str  # "in" or "out"
    wifi_ssid: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[Dict[str, Any]] = None

class LeaveRequest(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    employee_id: str
    leave_type: str  # sick, casual, earned, emergency
    start_date: str
    end_date: str
    days_requested: int
    reason: str
    status: str = "pending"  # pending, approved, rejected
    applied_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reviewed_at: Optional[datetime] = None
    reviewed_by: Optional[str] = None
    reviewer_comments: Optional[str] = None

class LeaveRequestCreate(BaseModel):
    leave_type: str
    start_date: str
    end_date: str
    days_requested: int
    reason: str

class LeaveApproval(BaseModel):
    status: str  # approved or rejected
    comments: Optional[str] = None

class RegularizationRequest(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    employee_id: str
    date: str
    requested_punch_in: Optional[str] = None
    requested_punch_out: Optional[str] = None
    reason: str
    status: str = "pending"
    applied_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reviewed_at: Optional[datetime] = None
    reviewed_by: Optional[str] = None
    reviewer_comments: Optional[str] = None

class RegularizationCreate(BaseModel):
    date: str
    requested_punch_in: Optional[str] = None
    requested_punch_out: Optional[str] = None
    reason: str

class DashboardStats(BaseModel):
    total_employees: int
    present_today: int
    on_leave: int
    pending_requests: int
    attendance_percentage: float

# Utility functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def validate_wifi_connection(wifi_ssid: Optional[str], ip_address: Optional[str]) -> bool:
    # Simulate office Wi-Fi validation
    # In real implementation, you would check against known office SSIDs and IP ranges
    office_ssids = ["BrandVerse_Office", "BV_Corp", "BrandVerse_WiFi"]
    office_ip_ranges = ["192.168.1.", "10.0.0.", "172.16."]
    
    ssid_valid = wifi_ssid in office_ssids if wifi_ssid else False
    ip_valid = any(ip_address.startswith(ip_range) for ip_range in office_ip_ranges) if ip_address else False
    
    return ssid_valid or ip_valid

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = await db.users.find_one({"id": user_id})
    if user is None:
        raise credentials_exception
    return User(**user)

async def get_current_hr_user(current_user: User = Depends(get_current_user)):
    if current_user.role != "hr_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. HR/Admin role required."
        )
    return current_user

# Authentication routes
@api_router.post("/auth/register", response_model=User)
async def register_user(user_data: UserCreate):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Hash password and create user
    hashed_password = get_password_hash(user_data.password)
    user_dict = user_data.dict()
    user_dict.pop("password")
    user_dict["hashed_password"] = hashed_password
    
    user = User(**user_dict)
    await db.users.insert_one(user.dict())
    
    return user

@api_router.post("/auth/login", response_model=Token)
async def login_user(login_data: UserLogin):
    user = await db.users.find_one({"email": login_data.email})
    if not user or not verify_password(login_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is inactive"
        )
    
    # Validate Wi-Fi connection for employees
    if user["role"] == "employee" and not validate_wifi_connection(login_data.wifi_ssid, login_data.ip_address):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access denied. Please connect to office Wi-Fi to login."
        )
    
    # Update last login
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"last_login": datetime.now(timezone.utc)}}
    )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["id"]}, expires_delta=access_token_expires
    )
    
    user_obj = User(**user)
    return Token(access_token=access_token, token_type="bearer", user=user_obj)

# Attendance routes
@api_router.post("/attendance/punch", response_model=AttendanceRecord)
async def punch_attendance(punch_data: AttendancePunch, current_user: User = Depends(get_current_user)):
    if current_user.role != "employee":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only employees can punch attendance"
        )
    
    # Validate Wi-Fi connection
    if not validate_wifi_connection(punch_data.wifi_ssid, punch_data.ip_address):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Wi-Fi connection. Please connect to office Wi-Fi."
        )
    
    today = datetime.now(timezone.utc).date().isoformat()
    
    # Find or create today's attendance record
    attendance = await db.attendance.find_one({
        "user_id": current_user.id,
        "date": today
    })
    
    if not attendance:
        attendance = AttendanceRecord(
            user_id=current_user.id,
            employee_id=current_user.employee_id,
            date=today,
            wifi_info={"ssid": punch_data.wifi_ssid, "ip": punch_data.ip_address}
        )
        await db.attendance.insert_one(attendance.dict())
    else:
        attendance = AttendanceRecord(**attendance)
    
    now = datetime.now(timezone.utc)
    
    if punch_data.punch_type == "in":
        if attendance.punch_in:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Already punched in today"
            )
        attendance.punch_in = now
    elif punch_data.punch_type == "out":
        if not attendance.punch_in:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Must punch in before punching out"
            )
        if attendance.punch_out:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Already punched out today"
            )
        attendance.punch_out = now
    
    # Update attendance record
    await db.attendance.update_one(
        {"id": attendance.id},
        {"$set": attendance.dict()}
    )
    
    return attendance

@api_router.get("/attendance/history", response_model=List[AttendanceRecord])
async def get_attendance_history(current_user: User = Depends(get_current_user)):
    query = {"user_id": current_user.id} if current_user.role == "employee" else {}
    
    attendance_records = await db.attendance.find(query).sort("date", -1).to_list(100)
    return [AttendanceRecord(**record) for record in attendance_records]

# Leave Management routes
@api_router.post("/leaves/request", response_model=LeaveRequest)
async def create_leave_request(leave_data: LeaveRequestCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != "employee":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only employees can request leave"
        )
    
    leave_request = LeaveRequest(
        user_id=current_user.id,
        employee_id=current_user.employee_id,
        **leave_data.dict()
    )
    
    await db.leave_requests.insert_one(leave_request.dict())
    return leave_request

@api_router.get("/leaves/my-requests", response_model=List[LeaveRequest])
async def get_my_leave_requests(current_user: User = Depends(get_current_user)):
    if current_user.role != "employee":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only employees can view their leave requests"
        )
    
    requests = await db.leave_requests.find({"user_id": current_user.id}).sort("applied_at", -1).to_list(100)
    return [LeaveRequest(**req) for req in requests]

@api_router.get("/leaves/pending", response_model=List[LeaveRequest])
async def get_pending_leave_requests(current_user: User = Depends(get_current_hr_user)):
    requests = await db.leave_requests.find({"status": "pending"}).sort("applied_at", 1).to_list(100)
    return [LeaveRequest(**req) for req in requests]

@api_router.put("/leaves/{request_id}/approve", response_model=LeaveRequest)
async def approve_leave_request(request_id: str, approval_data: LeaveApproval, current_user: User = Depends(get_current_hr_user)):
    leave_request = await db.leave_requests.find_one({"id": request_id})
    if not leave_request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Leave request not found"
        )
    
    update_data = {
        "status": approval_data.status,
        "reviewed_at": datetime.now(timezone.utc),
        "reviewed_by": current_user.id,
        "reviewer_comments": approval_data.comments
    }
    
    await db.leave_requests.update_one({"id": request_id}, {"$set": update_data})
    
    updated_request = await db.leave_requests.find_one({"id": request_id})
    return LeaveRequest(**updated_request)

# Regularization routes
@api_router.post("/regularization/request", response_model=RegularizationRequest)
async def create_regularization_request(reg_data: RegularizationCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != "employee":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only employees can request regularization"
        )
    
    reg_request = RegularizationRequest(
        user_id=current_user.id,
        employee_id=current_user.employee_id,
        **reg_data.dict()
    )
    
    await db.regularization_requests.insert_one(reg_request.dict())
    return reg_request

@api_router.get("/regularization/my-requests", response_model=List[RegularizationRequest])
async def get_my_regularization_requests(current_user: User = Depends(get_current_user)):
    if current_user.role != "employee":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only employees can view their regularization requests"
        )
    
    requests = await db.regularization_requests.find({"user_id": current_user.id}).sort("applied_at", -1).to_list(100)
    return [RegularizationRequest(**req) for req in requests]

@api_router.get("/regularization/pending", response_model=List[RegularizationRequest])
async def get_pending_regularization_requests(current_user: User = Depends(get_current_hr_user)):
    requests = await db.regularization_requests.find({"status": "pending"}).sort("applied_at", 1).to_list(100)
    return [RegularizationRequest(**req) for req in requests]

@api_router.put("/regularization/{request_id}/approve", response_model=RegularizationRequest)
async def approve_regularization_request(request_id: str, approval_data: LeaveApproval, current_user: User = Depends(get_current_hr_user)):
    reg_request = await db.regularization_requests.find_one({"id": request_id})
    if not reg_request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Regularization request not found"
        )
    
    update_data = {
        "status": approval_data.status,
        "reviewed_at": datetime.now(timezone.utc),
        "reviewed_by": current_user.id,
        "reviewer_comments": approval_data.comments
    }
    
    await db.regularization_requests.update_one({"id": request_id}, {"$set": update_data})
    
    updated_request = await db.regularization_requests.find_one({"id": request_id})
    return RegularizationRequest(**updated_request)

# Dashboard routes
@api_router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(current_user: User = Depends(get_current_hr_user)):
    today = datetime.now(timezone.utc).date().isoformat()
    
    total_employees = await db.users.count_documents({"role": "employee", "is_active": True})
    present_today = await db.attendance.count_documents({"date": today, "punch_in": {"$exists": True}})
    pending_leave_requests = await db.leave_requests.count_documents({"status": "pending"})
    pending_reg_requests = await db.regularization_requests.count_documents({"status": "pending"})
    
    # Calculate attendance percentage (last 30 days)
    thirty_days_ago = (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat()
    total_attendance_records = await db.attendance.count_documents({
        "date": {"$gte": thirty_days_ago}
    })
    
    attendance_percentage = (total_attendance_records / (total_employees * 30)) * 100 if total_employees > 0 else 0
    
    return DashboardStats(
        total_employees=total_employees,
        present_today=present_today,
        on_leave=0,  # Will calculate based on approved leaves for today
        pending_requests=pending_leave_requests + pending_reg_requests,
        attendance_percentage=min(attendance_percentage, 100)
    )

@api_router.get("/employees", response_model=List[User])
async def get_all_employees(current_user: User = Depends(get_current_hr_user)):
    employees = await db.users.find({"role": "employee"}).to_list(100)
    return [User(**emp) for emp in employees]

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

# Health check
@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc)}