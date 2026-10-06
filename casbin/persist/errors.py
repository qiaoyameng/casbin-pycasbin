# Copyright 2021 The Casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


class CasbinError(Exception):
    """base class for all casbin persistence errors."""


class TransactionNotSupportedError(CasbinError):
    """raised when an adapter cannot commit a batch atomically.

    A plain sequence of single-rule writes is not equivalent to a transaction:
    a failure in the middle leaves a mixed, partially applied policy behind.
    Adapters that cannot provide atomic commit must reject batch operations by
    raising this error rather than pretending otherwise.
    """


class TransactionCommitError(CasbinError):
    """raised when a transactional adapter fails to commit.

    The policy is guaranteed not to have taken effect in storage; the caller
    can safely retry the same batch.
    """


class PolicyNotificationError(CasbinError):
    """raised when the watcher could not be notified after a successful commit.

    The policy itself has already been committed and published, so callers can
    distinguish this state from a failed commit via ``committed``. Retrying the
    batch would attempt to apply the change a second time.
    """

    def __init__(self, message, committed=True):
        super().__init__(message)
        self.committed = committed
