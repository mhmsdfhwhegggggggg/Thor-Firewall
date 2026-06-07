"""Thor Firewall — Control Plane Configuration"""
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # Server
    port: int = 8080
    debug: bool = False
    log_level: str = "info"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # ClickHouse
    clickhouse_url: str = "clickhouse://localhost:9000/thor"

    # Agent gRPC
    agent_grpc_addr: str = "localhost:50051"

    # LLM
    llm_server_url: str = "http://localhost:8081"

    # CORS
    allowed_origins: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Security
    secret_key: str = "change-this-in-production"
    api_key_header: str = "X-Thor-API-Key"

    class Config:
        env_file = ".env"
        env_prefix = "THOR_"
