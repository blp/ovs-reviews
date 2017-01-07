#! /usr/bin/python
#
# Copyright (c) 2017 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import os

def build_docs():
    os.system("""
mkdir _rtd
cd _rtd
../configure
make dist-docs
""")

if __name__ == '__main__':
    if (sys.argv[1:] == ['install', '--force'] and
        os.environ['READTHEDOCS'] == 'True'):
        build_docs()
    else:
        sys.stderr.write('This program is only a hook for readthedocs.\n')
        sys.exit(1)
