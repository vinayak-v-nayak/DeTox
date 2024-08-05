import os
from dotenv import load_dotenv

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
import httpx

# Ensure you have session middleware configured in your FastAPI app
from starlette.middleware.sessions import SessionMiddleware
from fastapi import FastAPI

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="your_secret_key")

# getting OAuth 2.0 secret variables
load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
SCOPE = os.getenv("SCOPE")
REDIRECT_URI = os.getenv("REDIRECT_URI")
STATE = os.getenv("STATE")

# router for authorization URLs
auth_router = APIRouter()

@auth_router.get("/oauth2callback")
async def oauth2callback(request: Request, state: str = None, code: str = None):
    if code is None:
        auth_uri = (
            f"https://accounts.google.com/o/oauth2/v2/auth?response_type=code"
            f"&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}"
        )
        return RedirectResponse(auth_uri)
    else:
        if STATE and STATE != state:
            return HTMLResponse(f"Invalid state parameter. Please visit the <a href='/'>web-app</a> to complete the authorization.")
        
        data = {
            "code": code,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post("https://oauth2.googleapis.com/token", data=data)
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Failed to retrieve access token")

        credentials = response.json()
        request.session["credentials"] = credentials
        return RedirectResponse("/home")

@auth_router.get("/refresh-access-token")
async def refresh_access_token(request: Request):
    """Gets new access token using refresh token."""
    if "credentials" not in request.session or "refresh_token" not in request.session["credentials"]:
        return HTMLResponse(f"You need to <a href={request.url_for('oauth2callback')}>authorize</a> first before refreshing the token.")
    
    data = {
        "client_id": CLIENT_ID, 
        "client_secret": CLIENT_SECRET,
        "refresh_token": request.session["credentials"]["refresh_token"],
        "grant_type": "refresh_token"
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post("https://oauth2.googleapis.com/token", data=data)
    
    if response.status_code == 400:
        return HTMLResponse(f"Web-app's access to your YouTube account has been revoked. Please <a href={request.url_for('oauth2callback')}>authorize</a> to continue using the service.")
    
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Failed to refresh access token")
    
    credentials = response.json()
    request.session["credentials"]["access_token"] = credentials["access_token"]
    request.session["credentials"]["expires_in"] = credentials["expires_in"]
    
    redirect_url = request.session.get("redirect_url", request.url_for("home"))
    
    return RedirectResponse(redirect_url)

@auth_router.get("/revoke")
async def revoke(request: Request):
    """Revokes YouTube account access from the web-app."""
    if "credentials" not in request.session:
        return HTMLResponse(f"You need to <a href={request.url_for('oauth2callback')}>authorize</a> first before revoking the credentials.")
    
    credentials = request.session["credentials"]
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://oauth2.googleapis.com/revoke",
            params={"token": credentials["access_token"]},
            headers={"content-type": "application/x-www-form-urlencoded"}
        )
    
    if response.status_code == 403:
        return HTMLResponse("Cannot connect to YouTube right now. Please come back in a while.")
    
    if response.status_code == 401:
        request.session["redirect_url"] = str(request.url)
        return RedirectResponse(request.url_for("refresh_access_token"))
    
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Failed to revoke access token")
    
    return RedirectResponse(request.url_for("logout"))

@auth_router.get("/logout")
async def logout(request: Request):
    """Logs out the authenticated user by clearing out the session storage."""
    request.session.clear()
    return RedirectResponse(request.url_for("landing"))

app.include_router(auth_router)
