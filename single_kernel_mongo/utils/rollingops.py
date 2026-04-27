# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Definition of sync lock backend for rolling ops."""

import logging

from charmlibs.rollingops import SyncLockBackend
from tenacity import Retrying, retry_if_exception_type, stop_after_delay, stop_never, wait_fixed

from single_kernel_mongo.utils.mongo_connection import MongoConnection, NotReadyError

logger = logging.getLogger(__name__)


class MongoReplsetSyncLockBackend(SyncLockBackend):
    """Mongo-backed sync lock for replica-set membership changes.

    This does not create an external lock. It waits until MongoDB has no
    member currently in REMOVED/REMOVING-like state before allowing the
    critical section to proceed.
    """

    def __init__(self, state):
        self.state = state

    def acquire(self, timeout: int | None) -> None:
        """Blocks until the replica-set member removal can proceed.

        This is a best-effort synchronization check based on current
        replica-set state. It blocks until MongoDB reports no member
        removal is in progress.

        Raises:
            PyMongoError: If replica-set state cannot be queried.
            NotReadyError: If MongoDB is not yet ready to answer the request.
        """
        if timeout is None:
            stop_condition = stop_never
        else:
            stop_condition = stop_after_delay(timeout)

        retryer = Retrying(
            stop=stop_condition,
            wait=wait_fixed(3),
            retry=retry_if_exception_type(NotReadyError),
            reraise=True,
        )

        try:
            for attempt in retryer:
                with attempt:
                    with MongoConnection(self.state.mongo_config) as mongo:
                        rs_status = mongo.client.admin.command("replSetGetStatus")

                        if mongo.is_any_removing(rs_status):
                            logger.debug(
                                "Waiting for previous replica-set member removal to finish."
                            )
                            raise NotReadyError

                        logger.info("Mongo replica-set sync lock acquired.")
        except NotReadyError as exc:
            raise TimeoutError(
                "Timed out waiting for Mongo replica-set removal state to clear."
            ) from exc

    def release(self) -> None:
        """No-op: MongoDB replica-set state is the synchronization source."""
        logger.debug("Mongo replica-set sync lock released.")
