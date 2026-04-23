from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, validator
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
import asyncpg
import os
import logging
import json
import ipaddress
import time
from collections import defaultdict
from typing import Optional
from contextlib import asynccontextmanager
from prometheus_client import Counter, Histogram, generate_latest
from fastapi.responses import PlainTextResponse

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET", "changeme")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES", "30"))
DB_USER = os.getenv("DB_USER", "user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "password")
DB_NAME = os.getenv("DB_NAME", "auth_db")
DB_HOST = os.getenv("POSTGRES_HOST", "postgres")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

if ENVIRONMENT == "production" and SECRET_KEY in ("changeme", ""):
    raise RuntimeError("JWT_SECRET must be set to a secure value in production")

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
        "service": "auth-service",
        "message": message,
        **kwargs
    }
    logger.info(json.dumps(log_data))

# Private network ranges for metrics endpoint restriction
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

# In-memory rate limiter for login (use Redis in multi-instance deployments)
_login_attempts: dict = defaultdict(list)
RATE_LIMIT_WINDOW = 60   # seconds
RATE_LIMIT_MAX = 10       # max attempts per window per IP

def _check_login_rate_limit(client_ip: str) -> None:
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    _login_attempts[client_ip] = [t for t in _login_attempts[client_ip] if t > window_start]
    if len(_login_attempts[client_ip]) >= RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
            headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
        )
    _login_attempts[client_ip].append(now)

# Models
class UserLogin(BaseModel):
    username: str
    password: str
    
    @validator('username')
    def username_valid(cls, v):
        if not v or len(v) < 3:
            raise ValueError('Username must be at least 3 characters long')
        return v.lower().strip()
    
    @validator('password')
    def password_valid(cls, v):
        if not v or len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    role: Optional[str] = "user"
    
    @validator('username')
    def username_valid(cls, v):
        if not v or len(v) < 3:
            raise ValueError('Username must be at least 3 characters long')
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username can only contain letters, numbers, underscores and hyphens')
        return v.lower().strip()
    
    @validator('password')
    def password_strong(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one digit')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least one uppercase letter')
        return v

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class TokenData(BaseModel):
    username: Optional[str] = None
# Database
class DatabaseConnection:
    def __init__(self):
        self.pool = None
    
    async def init_pool(self):
        try:
            self.pool = await asyncpg.create_pool(
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                host=DB_HOST,
                port=DB_PORT,
                min_size=10,
                max_size=20,
                command_timeout=60
            )
            log_structured("Database pool created successfully")
        except Exception as e:
            log_structured("Failed to create database pool", error=str(e), level="ERROR")
            raise
    
    async def close_pool(self):
        if self.pool:
            await self.pool.close()
            log_structured("Database pool closed")
    
    @asynccontextmanager
    async def acquire(self):
        async with self.pool.acquire() as connection:
            yield connection

db_connection = DatabaseConnection()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# JWT functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    return token_data

# Metrics
REQUEST_COUNT = Counter('auth_service_requests_total', 'Total number of incoming requests', ['method', 'endpoint', 'status_code'])
REQUEST_LATENCY = Histogram('auth_service_request_duration_seconds', 'Request latency in seconds', ['method', 'endpoint', 'status_code'])

# FastAPI app with lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db_connection.init_pool()
    await init_database()
    yield
    # Shutdown
    await db_connection.close_pool()

app = FastAPI(
    title="Auth Service",
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

# Database initialization
async def init_database():
    async with db_connection.acquire() as conn:
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                hashed_password VARCHAR(255) NOT NULL,
                full_name VARCHAR(255),
                role VARCHAR(50) DEFAULT \'user\',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Add role column if upgrading from older schema
        await conn.execute('''
            ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT \'user\'
        ''')
        
        await conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        ''')
        
        await conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        ''')
        
        log_structured("Database initialized successfully")

# Routes
@app.get("/health")
async def health_check():
    try:
        async with db_connection.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {"status": "healthy", "service": "auth-service", "timestamp": datetime.now(timezone.utc).isoformat()}
    except Exception as e:
        log_structured("Health check failed", error=str(e), level="ERROR")
        raise HTTPException(status_code=503, detail="Service unavailable")

@app.get("/metrics")
async def metrics(request: Request):
    if not _is_internal_ip(request.client.host):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access restricted to internal network")
    return PlainTextResponse(generate_latest())

@app.post("/register", response_model=dict, status_code=status.HTTP_201_CREATED)
async def register(user: UserRegister):
    log_structured("Registration attempt", username=user.username, email=user.email)

    role = user.role if user.role in ("user", "admin") else "user"

    async with db_connection.acquire() as conn:
        # Check if user exists
        existing_user = await conn.fetchrow(
            "SELECT id FROM users WHERE username = $1 OR email = $2",
            user.username, user.email
        )

        if existing_user:
            log_structured("Registration failed - user exists", username=user.username)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already registered"
            )

        # Create user
        hashed_password = get_password_hash(user.password)

        try:
            user_id = await conn.fetchval(
                """
                INSERT INTO users (username, email, hashed_password, full_name, role)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id
                """,
                user.username, user.email, hashed_password, user.full_name, role
            )
            
            log_structured("User registered successfully", user_id=user_id, username=user.username)
            return {"message": "User registered successfully", "user_id": user_id}
            
        except Exception as e:
            log_structured("Registration error", error=str(e), level="ERROR")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to register user"
            )

@app.post("/login", response_model=Token)
async def login(user_credentials: UserLogin, request: Request):
    _check_login_rate_limit(request.client.host)
    log_structured("Login attempt", username=user_credentials.username)

    async with db_connection.acquire() as conn:
        db_user = await conn.fetchrow(
            "SELECT id, username, hashed_password, is_active, role FROM users WHERE username = $1",
            user_credentials.username
        )
        
        if not db_user:
            log_structured("Login failed - user not found", username=user_credentials.username)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        if not db_user["is_active"]:
            log_structured("Login failed - user inactive", username=user_credentials.username)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive"
            )
        
        if not verify_password(user_credentials.password, db_user["hashed_password"]):
            log_structured("Login failed - invalid password", username=user_credentials.username)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Update last login
        await conn.execute(
            "UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = $1",
            db_user["id"]
        )
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": db_user["username"], "user_id": db_user["id"], "role": db_user["role"]},
            expires_delta=access_token_expires
        )
        
        log_structured("Login successful", username=user_credentials.username, user_id=db_user["id"])
        
        return Token(
            access_token=access_token,
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )

@app.get("/verify", response_model=dict)
async def verify_token(current_user: TokenData = Depends(get_current_user)):
    async with db_connection.acquire() as conn:
        db_user = await conn.fetchrow(
            "SELECT is_active FROM users WHERE username = $1",
            current_user.username
        )
    if not db_user or not db_user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or does not exist",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"username": current_user.username, "valid": True}

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