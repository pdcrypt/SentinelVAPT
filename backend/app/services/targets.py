import uuid
from collections.abc import Sequence

from app.core.clock import Clock
from app.core.errors import ConflictError, DomainValidationError, NotFoundError
from app.models import Target, TargetAuthorization
from app.models.enums import AuthorizationStatus, TargetEnvironment
from app.repositories import ProjectRepository, TargetAuthorizationRepository, TargetRepository
from app.schemas.target import SCOPE_FIELDS, TargetAuthorizationIn, TargetCreate, TargetUpdate
from app.services.base import UnitOfWork
from app.services.scope import (
    Scope,
    authorization_status,
    validate_authorization_window,
    validate_scope,
)


class TargetService:
    """Owns the rules that make a target safe to assess: an explicit, validated
    scope and an acknowledged, time-bound authorization, kept as an append-only
    history of TargetAuthorization records."""

    def __init__(
        self,
        targets: TargetRepository,
        authorizations: TargetAuthorizationRepository,
        projects: ProjectRepository,
        uow: UnitOfWork,
        clock: Clock,
    ) -> None:
        self.targets = targets
        self.authorizations = authorizations
        self.projects = projects
        self.uow = uow
        self.clock = clock

    def create(self, project_id: uuid.UUID, data: TargetCreate) -> Target:
        if self.projects.get(project_id) is None:
            raise NotFoundError("project not found")
        self._ensure_name_available(project_id, data.name)

        # Validate everything before writing anything.
        scope = validate_scope(
            base_url=data.base_url,
            environment=data.environment,
            hosts=data.in_scope_hosts,
            ports=data.allowed_ports,
            path_prefixes=data.in_scope_path_prefixes,
            excluded_paths=data.excluded_paths,
        )
        target_id = uuid.uuid4()
        authorization = self._new_authorization(
            target_id, 1, scope, data.environment, data.authorization
        )

        # Target and its first authorization reference each other; the
        # target -> authorization foreign key is checked at commit.
        target = Target(
            id=target_id,
            project_id=project_id,
            name=data.name,
            current_authorization_id=authorization.id,
        )
        self.targets.add(target)
        self.authorizations.add(authorization)
        self.uow.commit()
        return target

    def get(self, target_id: uuid.UUID) -> Target:
        target = self.targets.get(target_id)
        if target is None:
            raise NotFoundError("target not found")
        return target

    def list_for_project(
        self, project_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[Target]:
        if self.projects.get(project_id) is None:
            raise NotFoundError("project not found")
        return self.targets.list_for_project(project_id, limit=limit, offset=offset)

    def list_authorizations(
        self, target_id: uuid.UUID, *, limit: int, offset: int
    ) -> Sequence[TargetAuthorization]:
        self.get(target_id)
        return self.authorizations.list_for_target(target_id, limit=limit, offset=offset)

    def update(self, target_id: uuid.UUID, data: TargetUpdate) -> Target:
        # Lock first, then read: concurrent updates of this target wait here and
        # see the result of the previous one, so they cannot combine stale fields.
        target = self.targets.get_for_update(target_id)
        if target is None:
            raise NotFoundError("target not found")
        current = target.current_authorization

        scope_changed = bool(data.model_fields_set & SCOPE_FIELDS)
        if scope_changed and data.authorization is None:
            raise DomainValidationError(
                "changing a target's scope requires re-acknowledging its authorization "
                "in the same request",
                field="authorization",
            )

        # Build and validate the complete resulting state before modifying anything.
        new_name = data.name if data.name is not None and data.name != target.name else None
        if new_name is not None:
            self._ensure_name_available(target.project_id, new_name, exclude_id=target.id)

        new_authorization = None
        if data.authorization is not None:
            environment = data.environment or current.environment
            scope = validate_scope(
                base_url=data.base_url or current.base_url,
                environment=environment,
                hosts=data.in_scope_hosts or current.in_scope_hosts,
                ports=data.allowed_ports or current.allowed_ports,
                path_prefixes=data.in_scope_path_prefixes or current.in_scope_path_prefixes,
                excluded_paths=(
                    data.excluded_paths
                    if data.excluded_paths is not None
                    else current.excluded_paths
                ),
            )
            new_authorization = self._new_authorization(
                target.id, current.version + 1, scope, environment, data.authorization
            )

        # Apply.
        if new_name is not None:
            target.name = new_name
            self.targets.flush()
        if new_authorization is not None:
            self.authorizations.add(new_authorization)
            self.targets.set_current_authorization(target, new_authorization)
        self.uow.commit()
        return target

    def delete(self, target_id: uuid.UUID) -> None:
        target = self.targets.get_for_update(target_id)
        if target is None:
            raise NotFoundError("target not found")
        # Authorization records are removed with the target only when nothing was
        # ever assessed under them; assessments keep the target (and history) alive.
        if self.targets.has_assessments(target.id):
            raise ConflictError("target still has assessments; delete them first")
        self.targets.delete(target)
        self.uow.commit()

    def authorization_status(self, authorization: TargetAuthorization) -> AuthorizationStatus:
        return authorization_status(
            authorization.valid_from, authorization.valid_until, self.clock()
        )

    def _new_authorization(
        self,
        target_id: uuid.UUID,
        version: int,
        scope: Scope,
        environment: TargetEnvironment,
        auth: TargetAuthorizationIn,
    ) -> TargetAuthorization:
        now = self.clock()
        validate_authorization_window(auth.valid_from, auth.valid_until, now)
        return TargetAuthorization(
            id=uuid.uuid4(),
            target_id=target_id,
            version=version,
            base_url=scope.base_url,
            environment=environment,
            in_scope_hosts=scope.hosts,
            allowed_ports=scope.ports,
            in_scope_path_prefixes=scope.path_prefixes,
            excluded_paths=scope.excluded_paths,
            authorized_by=auth.authorized_by,
            reference=auth.reference,
            notes=auth.notes,
            valid_from=auth.valid_from,
            valid_until=auth.valid_until,
            acknowledged_by=auth.acknowledged_by,
            # Server-controlled: the client cannot backdate an acknowledgment.
            acknowledged_at=now,
        )

    def _ensure_name_available(
        self, project_id: uuid.UUID, name: str, *, exclude_id: uuid.UUID | None = None
    ) -> None:
        if self.targets.name_exists(project_id, name, exclude_id=exclude_id):
            raise ConflictError(
                f"a target named '{name}' already exists in this project", field="name"
            )
