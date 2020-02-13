"""Tests for distutils.file_util."""
import unittest
import os
import shutil

from distutils.file_util import move_file, write_file, copy_file
from distutils import log
from distutils.tests import support
from test.test_support import run_unittest


requires_os_link = unittest.skipUnless(hasattr(os, "link"),
                                       "test requires os.link()")


class FileUtilTestCase(support.TempdirManager, unittest.TestCase):

    def _log(self, msg, *args):
        if len(args) > 0:
            self._logs.append(msg % args)
        else:
            self._logs.append(msg)

    def setUp(self):
        super(FileUtilTestCase, self).setUp()
        self._logs = []
        self.old_log = log.info
        log.info = self._log
        tmp_dir = self.mkdtemp()
        self.source = os.path.join(tmp_dir, 'f1')
        self.target = os.path.join(tmp_dir, 'f2')
        self.target_dir = os.path.join(tmp_dir, 'd1')

    def tearDown(self):
        log.info = self.old_log
        super(FileUtilTestCase, self).tearDown()

    def test_move_file_verbosity(self):
        f = open(self.source, 'w')
        try:
            f.write('some content')
        finally:
            f.close()

        move_file(self.source, self.target, verbose=0)
        wanted = []
        self.assertEqual(self._logs, wanted)

        # back to original state
        move_file(self.target, self.source, verbose=0)

        move_file(self.source, self.target, verbose=1)
        wanted = ['moving %s -> %s' % (self.source, self.target)]
        self.assertEqual(self._logs, wanted)

        # back to original state
        move_file(self.target, self.source, verbose=0)

        self._logs = []
        # now the target is a dir
        os.mkdir(self.target_dir)
        move_file(self.source, self.target_dir, verbose=1)
        wanted = ['moving %s -> %s' % (self.source, self.target_dir)]
        self.assertEqual(self._logs, wanted)

    def test_write_file(self):
        lines = ['a', 'b', 'c']
        dir = self.mkdtemp()
        foo = os.path.join(dir, 'foo')
        write_file(foo, lines)
        content = [line.strip() for line in open(foo).readlines()]
        self.assertEqual(content, lines)

    def test_copy_file(self):
        src_dir = self.mkdtemp()
        foo = os.path.join(src_dir, 'foo')
        write_file(foo, 'content')
        dst_dir = self.mkdtemp()
        copy_file(foo, dst_dir)
        self.assertTrue(os.path.exists(os.path.join(dst_dir, 'foo')))

    @requires_os_link
    def test_copy_file_hard_link(self):
        with open(self.source, 'w') as f:
            f.write('some content')
        st = os.stat(self.source)
        copy_file(self.source, self.target, link='hard')
        st2 = os.stat(self.source)
        st3 = os.stat(self.target)
        self.assertTrue(os.path.samestat(st, st2), (st, st2))
        self.assertTrue(os.path.samestat(st2, st3), (st2, st3))
        with open(self.source, 'r') as f:
            self.assertEqual(f.read(), 'some content')

    @requires_os_link
    def test_copy_file_hard_link_failure(self):
        # If hard linking fails, copy_file() falls back on copying file
        # (some special filesystems don't support hard linking even under
        #  Unix, see issue #8876).
        with open(self.source, 'w') as f:
            f.write('some content')
        st = os.stat(self.source)
        def _os_link(*args):
            raise OSError(0, "linking unsupported")
        old_link = os.link
        os.link = _os_link
        try:
            copy_file(self.source, self.target, link='hard')
        finally:
            os.link = old_link
        st2 = os.stat(self.source)
        st3 = os.stat(self.target)
        self.assertTrue(os.path.samestat(st, st2), (st, st2))
        self.assertFalse(os.path.samestat(st2, st3), (st2, st3))
        for fn in (self.source, self.target):
            with open(fn, 'r') as f:
                self.assertEqual(f.read(), 'some content')


def test_suite():
    return unittest.makeSuite(FileUtilTestCase)

if __name__ == "__main__":
    run_unittest(test_suite())
