# Copyright 2020, TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  utils.py

<Started>
  August 3, 2020.

<Author>
  Jussi Kukkonen

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Provide common utilities for TUF tests
"""

import datetime
import logging
from datetime import timezone

logger = logging.getLogger(__name__)


def get_date_n_days_in_past(days: int) -> datetime.datetime:
    return datetime.datetime.now(timezone.utc).replace(
        microsecond=0
    ) - datetime.timedelta(days=days)


def get_date_n_days_in_future(days: int) -> datetime.datetime:
    return datetime.datetime.now(timezone.utc).replace(
        microsecond=0
    ) + datetime.timedelta(days=days)
