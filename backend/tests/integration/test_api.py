"""Integration tests for Ch3ck3r API."""

import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.main import app
from app.db.session import get_db

# Use a test database
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test_ch3ck3r.db"


@pytest.fixture
async def db_session():
    """Create a fresh in-memory database for testing."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        from app.models import Base
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as session:
        yield session

    async with engine.begin() as conn:
        from app.models import Base
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture
async def client(db_session: AsyncSession):
    """HTTP client with test database session."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_health_live(client: AsyncClient):
    """Test the liveness endpoint."""
    response = await client.get("/api/v1/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "alive"


@pytest.mark.asyncio
async def test_health_ready(client: AsyncClient):
    """Test the readiness endpoint."""
    response = await client.get("/api/v1/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert "database" in data


@pytest.mark.asyncio
async def test_register_user(client: AsyncClient):
    """Test user registration."""
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "test@ch3ck3r.io",
            "password": "StrongP@ss123",
            "full_name": "Test User",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@ch3ck3r.io"
    assert data["role"] == "admin"  # First user is admin
    assert "id" in data


@pytest.mark.asyncio
async def test_login(client: AsyncClient):
    """Test user login and token retrieval."""
    # Register first
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "login@ch3ck3r.io",
            "password": "StrongP@ss123",
            "full_name": "Login User",
        },
    )

    # Login
    response = await client.post(
        "/api/v1/auth/login",
        data={
            "username": "login@ch3ck3r.io",
            "password": "StrongP@ss123",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_project_crud(client: AsyncClient):
    """Test project creation, listing, and retrieval."""
    # Register + login
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "proj@ch3ck3r.io",
            "password": "StrongP@ss123",
            "full_name": "Project User",
        },
    )
    login_resp = await client.post(
        "/api/v1/auth/login",
        data={"username": "proj@ch3ck3r.io", "password": "StrongP@ss123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create project
    create_resp = await client.post(
        "/api/v1/projects",
        json={
            "name": "Test Project",
            "description": "Integration test project",
            "target_url": "https://api.example.com",
            "repo_url": "https://github.com/example/api",
        },
        headers=headers,
    )
    assert create_resp.status_code == 201
    project = create_resp.json()
    assert project["name"] == "Test Project"

    # List projects
    list_resp = await client.get("/api/v1/projects", headers=headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) >= 1

    # Get single project
    get_resp = await client.get(f"/api/v1/projects/{project['id']}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "Test Project"


@pytest.mark.asyncio
async def test_scan_execution(client: AsyncClient):
    """Test scan creation and execution."""
    # Auth setup
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "scan@ch3ck3r.io",
            "password": "StrongP@ss123",
            "full_name": "Scan User",
        },
    )
    login_resp = await client.post(
        "/api/v1/auth/login",
        data={"username": "scan@ch3ck3r.io", "password": "StrongP@ss123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create project
    proj_resp = await client.post(
        "/api/v1/projects",
        json={
            "name": "Scan Test",
            "target_url": "https://httpbin.org",
        },
        headers=headers,
    )
    project = proj_resp.json()

    # Create scan
    scan_resp = await client.post(
        "/api/v1/scans",
        json={
            "project_id": project["id"],
            "scan_type": "openapi",
            "target": "https://httpbin.org",
        },
        headers=headers,
    )
    assert scan_resp.status_code == 201
    scan = scan_resp.json()
    assert scan["status"] == "pending"

    # Execute scan
    exec_resp = await client.post(
        f"/api/v1/scans/{scan['id']}/execute",
        headers=headers,
    )
    assert exec_resp.status_code == 200
    result = exec_resp.json()
    assert result["status"] in ("completed", "failed")

    # Get scan details
    get_resp = await client.get(
        f"/api/v1/scans/{scan['id']}",
        headers=headers,
    )
    assert get_resp.status_code == 200


@pytest.mark.asyncio
async def test_get_scanners(client: AsyncClient):
    """Test the scanners listing endpoint."""
    response = await client.get("/api/v1/scans/scanners")
    assert response.status_code == 200
    data = response.json()
    assert "scanners" in data
    assert len(data["scanners"]) >= 1


@pytest.mark.asyncio
async def test_unauthorized_access(client: AsyncClient):
    """Test that unauthenticated requests are rejected."""
    response = await client.get("/api/v1/projects")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_scan_stats(client: AsyncClient):
    """Test the scan statistics endpoint."""
    # Auth
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "stats@ch3ck3r.io",
            "password": "StrongP@ss123",
            "full_name": "Stats User",
        },
    )
    login_resp = await client.post(
        "/api/v1/auth/login",
        data={"username": "stats@ch3ck3r.io", "password": "StrongP@ss123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = await client.get("/api/v1/scans/stats/overview", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "total_findings" in data
