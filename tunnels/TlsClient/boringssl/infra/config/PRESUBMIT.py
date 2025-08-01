# Copyright 2025 The BoringSSL Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Enforces consistency in lucicfg definitions for BoringSSL's CI and CQ.

Run by the presubmit API in depot_tools, e.g. by running `git cl presubmit`.
"""

PRESUBMIT_VERSION = '2.0.0'

def CheckLucicfgGenOutputMain(input_api, output_api):
  return input_api.RunTests(input_api.canned_checks.CheckLucicfgGenOutput(
      input_api, output_api, 'main.star'))
