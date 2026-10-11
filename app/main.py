from fastapi import FastAPI

from app.routers.auth import router as auth_router
from app.routers.users import router as users_router


app = FastAPI(
    title="JWT Login API",
    description="Authentication API using FastAPI, PostgreSQL and JWT",
    version="1.0.0",
)


app.include_router(auth_router)
app.include_router(users_router)


@app.get("/")
def root():
    return {
        "message": "JWT Login API is running",
    }