"""Platform authentication (ADR 0014, Phase 9 M2).

These endpoints establish only *who* the user is. They grant no project
access and do not change how any other route behaves (M3/M4 add route
authorization). There is no registration, password reset or user
administration here.
"""

from fastapi import APIRouter, Depends, Response, status

from app.api.authz import authenticated, public
from app.api.deps import AuditContextDep, AuthServiceDep, PrincipalDep
from app.schemas.auth import (
    CurrentUser,
    LoginRequest,
    MeResponse,
    PasswordChangeRequest,
    SessionInfo,
    SessionResponse,
)
from app.services.auth import IssuedSession, Principal

router = APIRouter(prefix="/auth", tags=["auth"])

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _me(principal: Principal) -> MeResponse:
    return MeResponse(
        user=CurrentUser(
            id=principal.user_id,
            username=principal.username,
            display_name=principal.display_name,
            global_role=principal.global_role,
            must_change_password=principal.must_change_password,
        ),
        session=SessionInfo(
            created_at=principal.session_created_at,
            idle_expires_at=principal.idle_expires_at,
            expires_at=principal.expires_at,
        ),
    )


def _issued(issued: IssuedSession) -> SessionResponse:
    me = _me(issued.principal)
    return SessionResponse(user=me.user, session=me.session, token=issued.token)


@router.post(
    "/login",
    dependencies=[Depends(public())],
    response_model=SessionResponse,
    responses={401: {"description": "Invalid username or password (always the same response)"}},
)
def login(
    data: LoginRequest, auth: AuthServiceDep, context: AuditContextDep, response: Response
) -> SessionResponse:
    """Start a session. Unknown user, wrong password, disabled account and
    throttling all return the same 401."""
    response.headers.update(NO_STORE)
    return _issued(auth.login(data.username, data.password, context))


@router.post(
    "/logout",
    dependencies=[Depends(authenticated(allow_password_change_pending=True))],
    status_code=status.HTTP_204_NO_CONTENT,
)
def logout(principal: PrincipalDep, auth: AuthServiceDep, context: AuditContextDep) -> Response:
    """End the current session. The token stops working immediately."""
    auth.logout(principal, context)
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers=NO_STORE)


@router.get(
    "/me",
    dependencies=[Depends(authenticated(allow_password_change_pending=True))],
    response_model=MeResponse,
)
def me(principal: PrincipalDep, response: Response) -> MeResponse:
    """The authenticated platform user and session. No project information."""
    response.headers.update(NO_STORE)
    return _me(principal)


@router.post(
    "/password",
    dependencies=[Depends(authenticated(allow_password_change_pending=True))],
    response_model=SessionResponse,
    responses={403: {"description": "The current password is incorrect"}},
)
def change_password(
    data: PasswordChangeRequest,
    principal: PrincipalDep,
    auth: AuthServiceDep,
    context: AuditContextDep,
    response: Response,
) -> SessionResponse:
    """Change the password. Every session of the user ends, including this
    one; the response carries a fresh session token."""
    response.headers.update(NO_STORE)
    return _issued(
        auth.change_password(principal, data.current_password, data.new_password, context)
    )
