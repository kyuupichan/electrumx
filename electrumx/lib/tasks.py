# Copyright (c) 2018, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# and warranty status of this software.

'''Concurrency via tasks and threads.'''

from aiorpcx import TaskSet

import electrumx.lib.util as util


class Tasks(object):
    # Functionality here will be incorporated into aiorpcX's TaskSet
    # after experience is gained.

    def __init__(self, *, loop=None):
        self.tasks = TaskSet(loop=loop)
        self.logger = util.class_logger(__name__, self.__class__.__name__)
        # Pass through until integrated
        self.loop = self.tasks.loop
        self.wait = self.tasks.wait

    async def run_in_thread(self, func, *args):
        '''Run a function in a separate thread, and await its completion.'''
        return await self.loop.run_in_executor(None, func, *args)

    def create_task(self, coro, daemon=True):
        '''Schedule the coro to be run.'''
        task = self.tasks.create_task(coro)
        if daemon:
            task.add_done_callback(self._check_task_exception)
        return task

    def _check_task_exception(self, task):
        '''Check a task for exceptions.'''
        try:
            if not task.cancelled():
                task.result()
        except Exception as e:
            self.logger.exception(f'uncaught task exception: {e}')

    async def cancel_all(self, wait=True):
        '''Cancels all tasks and waits for them to complete.'''
        self.tasks.cancel_all()
        if wait:
            await self.tasks.wait()
