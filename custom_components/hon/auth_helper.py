import logging
import re
import urllib.parse
from typing import Optional, Dict, Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

AUTH_URL = "https://account2.hon-smarthome.com"
CLIENT_ID = "3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6"
REDIRECT_URI = "hon://mobilesdk/detect/oauth/done"

DEFAULT_FWUID = "X-785-gIn7v0R6L7N3Z6g"  # Fallback FWUID


async def async_get_token(email: str, password: str, session: aiohttp.ClientSession) -> Optional[Dict[str, str]]:
    """Get id_token and refresh_token using Salesforce Aura login flow."""
    fwuid = DEFAULT_FWUID
    
    # Step 1: Login via Aura API
    url = f"{AUTH_URL}/s/sfsites/aura?r=3&other.LightningLoginCustom.login=1"
    message = {
        "actions": [
            {
                "id": "75;a",
                "descriptor": "serviceComponent://ui.login.LightningLoginCustomController/ACTION$login",
                "callingDescriptor": "markup://c:honLogin",
                "params": {
                    "username": email,
                    "password": password,
                    "startUrl": f"/setup/secur/RemoteAccessAuthorizationPage.apexp?source={CLIENT_ID}&display=touch",
                },
            }
        ]
    }
    
    for _ in range(2):  # Allow one retry for clientOutOfSync
        aura_context = {"mode": "PROD", "fwuid": fwuid, "app": "siteforce:communityApp"}
        payload = {
            "message": str(message).replace("'", '"'),
            "aura.context": str(aura_context).replace("'", '"'),
            "aura.token": None,
        }
        
        async with session.post(url, data=payload) as resp:
            if resp.status != 200:
                _LOGGER.error("Aura login failed with status %s", resp.status)
                return None
                
            data = await resp.json()
            
            # Check for errors/sync issues
            if data.get("actions") and data["actions"][0].get("state") == "ERROR":
                errors = data["actions"][0].get("error", [])
                if errors and "clientOutOfSync" in str(errors):
                    # Extract expected fwuid
                    match = re.search(r"Expected: ([\w\-]+)", str(errors))
                    if match:
                        fwuid = match.group(1)
                        _LOGGER.info("Updating FWUID to %s and retrying login", fwuid)
                        continue
                _LOGGER.error("Aura login error: %s", errors)
                return None
            
            # Extract frontdoor URL
            try:
                frontdoor_url = data["events"][0]["attributes"]["values"]["url"]
            except (KeyError, IndexError):
                _LOGGER.error("Could not find frontdoor URL in Aura response")
                return None
                
    # Step 2: Follow redirects to get session cookies
    async with session.get(frontdoor_url) as resp:
        if resp.status != 200:
            _LOGGER.error("Frontdoor access failed")
            return None

    # Visit ProgressiveLogin
    prog_url = f"{AUTH_URL}/apex/ProgressiveLogin?retURL=%2Fsetup%2Fsecur%2FRemoteAccessAuthorizationPage.apexp?source={CLIENT_ID}"
    async with session.get(prog_url) as resp:
        if resp.status != 200:
            _LOGGER.error("ProgressiveLogin access failed")
            return None

    # Step 3: OAuth Authorization
    oauth_url = (
        f"{AUTH_URL}/services/oauth2/authorize?"
        f"response_type=token+id_token&client_id={CLIENT_ID}&"
        f"redirect_uri={urllib.parse.quote(REDIRECT_URI)}&display=touch&"
        f"scope=api%20openid%20refresh_token%20web&nonce=any_nonce"
    )
    
    async with session.get(oauth_url) as resp:
        text = await resp.text()
        
        if "ChangePassword" in text:
            _LOGGER.warning("hOn requires a password change. Please log in via the app or website.")
            return {"error": "change_password"}

        # Extract tokens from the response (usually in a script redirect)
        # The gvigroux/hon method:
        try:
            # Try to find tokens in the URL-like parts of the response
            # Sometimes it's in a location.replace('...')
            match = re.search(r"id_token=([^&'\s]+)", text)
            id_token = match.group(1) if match else None
            
            match = re.search(r"refresh_token=([^&'\s]+)", text)
            refresh_token = match.group(1) if match else None
            
            if id_token and refresh_token:
                return {
                    "id_token": id_token,
                    "refresh_token": refresh_token
                }
        except Exception as exc:
            _LOGGER.error("Failed to extract tokens: %s", exc)

    _LOGGER.error("Could not obtain tokens from Salesforce flow")
    return None
