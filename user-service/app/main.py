from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, validator
from motor.motor_asyncio import AsyncIOMotorClient
from jose import jwt, JWTError
from datetime import datetime, timezone
import logging
import os
import json
import ipaddress
import time
from typing import Optional, List
from bson import ObjectId
from contextlib import asynccontextmanager
from prometheus_client import Counter, Histogram, generate_latest
from fastapi.responses import PlainTextResponse

# Configuration
MONGO_HOST = os.getenv("MONGO_HOST", "mongo")
MONGO_PORT = int(os.getenv("MONGO_PORT", "27017"))
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "user_db")
SECRET_KEY = os.getenv("JWT_SECRET", "changeme")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Logging configuration
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=getattr(logging, LOG_LEVEL.upper())
)
logger = logging.getLogger(__name__)

def log_structured(message: str, **kwargs):
    log_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": ENVIRONMENT,
        "service": "user-service",
        "message": message,
        **kwargs
    }
    logger.info(json.dumps(log_data))

_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

def _is_internal_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False

# MongoDB helpers
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return ObjectId(v)

    @classmethod
    # def __modify_schema__(cls, field_schema):
    def __get_pydantic_json_schema__(cls, field_schema):
        field_schema.update(type="string")

# Models
class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: Optional[str] = Field(None, max_length=100)
    
    @validator('username')
    def username_valid(cls, v):
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username can only contain letters, numbers, underscores and hyphens')
        return v.lower().strip()

class UserCreate(UserBase):
    role: Optional[str] = Field("user", pattern="^(user|admin)$")

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(None, max_length=100)
    is_active: Optional[bool] = None

class UserInDB(UserBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    created_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True
    role: str = "user"
    
    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}

class UserResponse(UserBase):
    id: str
    created_by: str
    created_at: datetime
    is_active: bool
    role: str

class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[int] = None
    role: str = "user"

# Database
class MongoDB:
    client: AsyncIOMotorClient = None
    database = None

db = MongoDB()

# Metrics
REQUEST_COUNT = Counter('user_service_requests_total', 'Total number of incoming requests', ['method', 'endpoint', 'status_code'])
REQUEST_LATENCY = Histogram('user_service_request_duration_seconds', 'Request latency in seconds', ['method', 'endpoint', 'status_code'])

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        db.client = AsyncIOMotorClient(f"mongodb://{MONGO_HOST}:{MONGO_PORT}")
        db.database = db.client[MONGO_DB_NAME]
        
        # Create indexes
        await db.database.users.create_index("username", unique=True)
        await db.database.users.create_index("email", unique=True)
        await db.database.users.create_index("created_at")
        
        log_structured("MongoDB connected successfully")
    except Exception as e:
        log_structured("Failed to connect to MongoDB", error=str(e), level="ERROR")
        raise
    
    yield
    
    # Shutdown
    if db.client:
        db.client.close()
        log_structured("MongoDB connection closed")

app = FastAPI(
    title="User Service v1",
    version="1.0.0",
    lifespan=lifespan
)

# Middleware for metrics
@app.middleware("http")
async def collect_metrics(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time

    endpoint = request.url.path
    method = request.method
    status_code = response.status_code

    REQUEST_COUNT.labels(method=method, endpoint=endpoint, status_code=status_code).inc()
    REQUEST_LATENCY.labels(method=method, endpoint=endpoint, status_code=status_code).observe(process_time)

    return response

# Security
security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> TokenData:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        role: str = payload.get("role", "user")

        if username is None:
            raise credentials_exception

        return TokenData(username=username, user_id=user_id, role=role)
    except JWTError as e:
        log_structured("JWT validation error", error=str(e), level="WARNING")
        raise credentials_exception

# Routes
@app.get("/health")
async def health_check():
    try:
        # Check MongoDB connection
        await db.client.admin.command('ping')
        return {
            "status": "healthy",
            "service": "user-service",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": "connected"
        }
    except Exception as e:
        log_structured("Health check failed", error=str(e), level="ERROR")
        return {
            "status": "unhealthy",
            "service": "user-service",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": "disconnected"
        }

@app.get("/metrics")
async def metrics(request: Request):
    if not _is_internal_ip(request.client.host):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access restricted to internal network")
    return PlainTextResponse(generate_latest())

@app.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user: UserCreate,
    current_user: TokenData = Depends(get_current_user)
):
    log_structured("Creating user", username=user.username, created_by=current_user.username)
    
    # Check if user exists
    existing_user = await db.database.users.find_one({
        "$or": [
            {"username": user.username},
            {"email": user.email}
        ]
    })
    
    if existing_user:
        log_structured("User creation failed - duplicate", username=user.username)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists"
        )
    
    # Create user document
    user_doc = UserInDB(
        **user.dict(),
        created_by=current_user.username
    )
    
    try:
        result = await db.database.users.insert_one(user_doc.dict(by_alias=True))
        created_user = await db.database.users.find_one({"_id": result.inserted_id})
        
        log_structured("User created successfully", user_id=str(result.inserted_id))
        
        return UserResponse(
            id=str(created_user["_id"]),
            username=created_user["username"],
            email=created_user["email"],
            full_name=created_user.get("full_name"),
            created_by=created_user["created_by"],
            created_at=created_user["created_at"],
            is_active=created_user["is_active"],
            role=created_user["role"]
        )
    except Exception as e:
        log_structured("User creation error", error=str(e), level="ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )

@app.get("/", response_model=List[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    is_active: Optional[bool] = None,
    current_user: TokenData = Depends(get_current_user)
):
    log_structured("Listing users", requested_by=current_user.username)
    
    # Build query
    query = {}
    if is_active is not None:
        query["is_active"] = is_active
    
    try:
        cursor = db.database.users.find(query).skip(skip).limit(limit).sort("created_at", -1)
        users = await cursor.to_list(length=limit)
        
        log_structured("Users retrieved", count=len(users))
        
        return [
            UserResponse(
                id=str(user["_id"]),
                username=user["username"],
                email=user["email"],
                full_name=user.get("full_name"),
                created_by=user["created_by"],
                created_at=user["created_at"],
                is_active=user["is_active"],
                role=user["role"]
            )
            for user in users
        ]
    except Exception as e:
        log_structured("Error listing users", error=str(e), level="ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve users"
        )

@app.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: TokenData = Depends(get_current_user)
):
    log_structured("Getting user", user_id=user_id, requested_by=current_user.username)
    
    if not ObjectId.is_valid(user_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID format"
        )
    
    user = await db.database.users.find_one({"_id": ObjectId(user_id)})
    
    if not user:
        log_structured("User not found", user_id=user_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(
        id=str(user["_id"]),
        username=user["username"],
        email=user["email"],
        full_name=user.get("full_name"),
        created_by=user["created_by"],
        created_at=user["created_at"],
        is_active=user["is_active"],
        role=user["role"]
    )

@app.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_update: UserUpdate,
    current_user: TokenData = Depends(get_current_user)
):
    log_structured("Updating user", user_id=user_id, updated_by=current_user.username)
    
    if not ObjectId.is_valid(user_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID format"
        )
    
    # Build update document
    update_data = {k: v for k, v in user_update.dict().items() if v is not None}
    
    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update"
        )
    
    update_data["updated_at"] = datetime.now(timezone.utc)
    
    try:
        result = await db.database.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        updated_user = await db.database.users.find_one({"_id": ObjectId(user_id)})
        
        log_structured("User updated successfully", user_id=user_id)
        
        return UserResponse(
            id=str(updated_user["_id"]),
            username=updated_user["username"],
            email=updated_user["email"],
            full_name=updated_user.get("full_name"),
            created_by=updated_user["created_by"],
            created_at=updated_user["created_at"],
            is_active=updated_user["is_active"],
            role=updated_user["role"]
        )
    except Exception as e:
        log_structured("User update error", error=str(e), level="ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user"
        )

@app.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    current_user: TokenData = Depends(get_current_user)
):
    log_structured("Deleting user", user_id=user_id, deleted_by=current_user.username)
    
    if not ObjectId.is_valid(user_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID format"
        )
    
    # Soft delete - just mark as inactive
    result = await db.database.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"is_active": False, "updated_at": datetime.utcnow()}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    log_structured("User deleted successfully", user_id=user_id)

# Error handlers
@app.exception_handler(ValueError)
async def value_error_handler(request, exc):
    return HTTPException(status_code=400, detail=str(exc))

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    log_structured("Unhandled exception", error=str(exc), level="ERROR")
    return HTTPException(status_code=500, detail="Internal server error")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 