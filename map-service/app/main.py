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
from prometheus_client import Counter, Histogram, generate_latest
from contextlib import asynccontextmanager
from bson import ObjectId
from fastapi.responses import PlainTextResponse, Response, JSONResponse
from typing import Optional, List
from bson.errors import InvalidId

# Configuration
MONGO_HOST = os.getenv("MONGO_HOST", "mongo")
MONGO_PORT = int(os.environ.get("MONGO_PORT", "27017"))
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "map_db")
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
        "service": "map-service",
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
    def validate(cls, v, handler=None):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, field_schema):
        field_schema.update(type="string")

    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type, _handler):
        from pydantic_core import core_schema
        return core_schema.json_or_python_schema(
            json_schema=core_schema.str_schema(),  # Fixed: Use str_schema() instead of StringSchema()
            python_schema=core_schema.union_schema([
                core_schema.is_instance_schema(ObjectId),
                core_schema.chain_schema([
                    core_schema.str_schema(),  # Fixed: Use str_schema() instead of StringSchema()
                    core_schema.no_info_plain_validator_function(cls.validate)
                ])
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda x: str(x)
            )
        )


    class Config:
        populate_by_name = True  # Fixed: Changed from 'allow_population_by_field_name'
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}

# class MapBase(BaseModel):
#     name: str
#     description: str
#     created_at: datetime = Field(default_factory=datetime.utcnow)
#     updated_at: datetime = Field(default_factory=datetime.utcnow)
#     created_by: str
#     updated_by: str 

class Coordinates(BaseModel):
    latitude: float = Field(..., ge=-90.0, le=90.0)
    longitude: float = Field(..., ge=-180.0, le=180.0)
    altitude: Optional[float] = Field(default=None)

class MapBase(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    description: str = Field(..., max_length=500)
    region: Optional[str] = Field(default=None)
    coordinates: Optional[Coordinates] = None
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str
    updated_by: str

class MapCreate(MapBase):
    pass

class MapUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None   

class MapInDB(MapBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}

class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[int] = None

# Database
class MongoDB:
    client: AsyncIOMotorClient = None
    database = None

db = MongoDB()


# Metrics
REQUEST_COUNT = Counter('map_service_requests_total', 'Total number of incoming requests', ['method', 'endpoint', 'status_code'])
REQUEST_LATENCY = Histogram('map_service_request_duration_seconds', 'Request latency in seconds', ['method', 'endpoint', 'status_code'])

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        db.client = AsyncIOMotorClient(f"mongodb://{MONGO_HOST}:{MONGO_PORT}")
        db.database = db.client[MONGO_DB_NAME]

        # Create indexes
        await db.database.maps.create_index("created_at")
        
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
    title="Map Service v1",
    version="1.0.0",
    lifespan=lifespan
)

# Middleware for metrics
@app.middleware("http")
async def collect_metrics(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time

    # Metrics
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

        if username is None:
            raise credentials_exception
            
        return TokenData(username=username, user_id=user_id)
    except JWTError as e:
        log_structured("JWT validation error", error=str(e), level="WARNING")
        raise credentials_exception 

def validate_object_id(map_id: str):
    try:
        return ObjectId(map_id)
    except (InvalidId, TypeError):
        raise HTTPException(status_code=400, detail="Invalid map_id")

# Routes
@app.get("/health")
async def health_check():
    try:
        # Check MongoDB connection
        await db.client.admin.command('ping')
        return {
            "status": "healthy",
            "service": "map-service",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": "connected"
        }
    except Exception as e:
        log_structured("Health check failed", error=str(e), level="ERROR")
        return {
            "status": "unhealthy",
            "service": "map-service",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": "disconnected"
        }

@app.get("/metrics")
async def metrics(request: Request):
    if not _is_internal_ip(request.client.host):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access restricted to internal network")
    return PlainTextResponse(generate_latest())

@app.post('/', response_model=MapInDB, status_code=status.HTTP_201_CREATED)
async def create_map(
    map: MapCreate,
    current_user: TokenData = Depends(get_current_user)
):
    map_dict = map.model_dump()
    map_dict['created_by'] = current_user.username
    map_dict['updated_by'] = current_user.username
    map_dict['created_at'] = datetime.now(timezone.utc)
    map_dict['updated_at'] = datetime.now(timezone.utc)

    result = await db.database.maps.insert_one(map_dict)
    created_map = await db.database.maps.find_one({"_id": result.inserted_id})
    return MapInDB(**created_map)

@app.get('/', response_model=List[MapInDB])
async def list_maps(
    skip: int = 0,
    limit: int = 100,
    current_user: TokenData = Depends(get_current_user)
):
    maps = await db.database.maps.find().skip(skip).limit(limit).to_list(length=limit)
    return maps

@app.get('/{map_id}', response_model=MapInDB)
async def get_map(map_id: str, current_user: TokenData = Depends(get_current_user)):
    map_obj_id = validate_object_id(map_id)
    map_doc = await db.database.maps.find_one({"_id": map_obj_id})
    if not map_doc:
        raise HTTPException(status_code=404, detail="Map not found")
    return MapInDB(**map_doc)

@app.put('/{map_id}', response_model=MapInDB)
async def update_map(map_id: str, map: MapUpdate, current_user: TokenData = Depends(get_current_user)):
    map_obj_id = validate_object_id(map_id)
    map_doc = await db.database.maps.find_one({"_id": map_obj_id})
    if not map_doc:
        raise HTTPException(status_code=404, detail="Map not found")
    if map_doc["created_by"] != current_user.username:
        raise HTTPException(status_code=403, detail="Not authorized to update this map")
    update_data = {k: v for k, v in map.model_dump().items() if v is not None}
    update_data['updated_by'] = current_user.username
    update_data['updated_at'] = datetime.now(timezone.utc)
    result = await db.database.maps.update_one({"_id": map_obj_id}, {"$set": update_data})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Map not found")
    updated_map = await db.database.maps.find_one({"_id": map_obj_id})
    return MapInDB(**updated_map)

@app.delete('/{map_id}', status_code=status.HTTP_204_NO_CONTENT)
async def delete_map(map_id: str, current_user: TokenData = Depends(get_current_user)):
    map_obj_id = validate_object_id(map_id)
    map_doc = await db.database.maps.find_one({"_id": map_obj_id})
    if not map_doc:
        raise HTTPException(status_code=404, detail="Map not found")
    if map_doc["created_by"] != current_user.username:
        raise HTTPException(status_code=403, detail="Not authorized to delete this map")
    result = await db.database.maps.delete_one({"_id": map_obj_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Map not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@app.exception_handler(ValueError)
async def value_error_handler(request, exc):
    return JSONResponse(status_code=400, content={"detail": str(exc)})

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    error_id = str(ObjectId())
    error_message = str(exc) if ENVIRONMENT == "development" else "An unexpected error occurred"
    log_structured(
        "Unhandled exception",
        error_id=error_id,
        error_type=exc.__class__.__name__,
        error_message=error_message,
        level="ERROR"
    )
    return JSONResponse(
        status_code=500,
        content={
            "error_id": error_id,
            "message": "Internal server error",
            "details": error_message if ENVIRONMENT == "development" else None
        }
    )

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000) 




# from fastapi import FastAPI, HTTPException, Depends, status, Request
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# from pydantic import BaseModel, EmailStr, Field, validator
# from motor.motor_asyncio import AsyncIOMotorClient
# from jose import jwt, JWTError
# from datetime import datetime
# import logging
# import os
# import json
# import uvicorn

# # Configuration
# MONGO_HOST = os.getenv("MONGO_HOST", "mongo")
# MONGO_PORT = int(os.environ.get("MONGO_PORT", "27017"))
# MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "map_db")
# SECRET_KEY = os.getenv("JWT_SECRET", "changeme")
# ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
# ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
# LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# app = FastAPI()

# @app.get("/health")
# def health_check():
#     return {'status': 'healthy'}

# @app.get('/maps')
# def get_map():
#     # Add your map retrieval logic here
#     return {'map': 'sample map'}

# if __name__ == '__main__':
#     uvicorn.run(app, host='0.0.0.0', port=8000)