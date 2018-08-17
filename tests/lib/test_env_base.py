# Tests of server/env.py

import os

import pytest

from electrumx.lib.env_base import EnvBase


os.environ.update({
    'int': '32',
    'intspace': ' 32 ',
    'true': 'x',
    'false': '',
    'space': ' ',
})

def test_default():
    e = EnvBase()
    assert e.default('int', '33') == '32'
    assert e.default('baz', 'z') == 'z'

def test_boolean():
    e = EnvBase()
    assert e.boolean('true', False)
    assert not e.boolean('false', True)
    assert not e.boolean('space', True)
    assert e.boolean('missing', True)
    assert not e.boolean('missing', False)

def test_required():
    e = EnvBase()
    assert e.required('true') == 'x'
    with pytest.raises(e.Error):
        e.required('missing')

def test_integer():
    e = EnvBase()
    assert e.integer('int', 33) == 32
    assert e.integer('missing', 33) == 33
    assert e.integer('intspace', 33) == 32
    assert e.integer('missing', None) is None
    with pytest.raises(e.Error):
        e.integer('true', 1)

def test_obsolete():
    e = EnvBase()
    with pytest.raises(e.Error):
        e.obsolete(['z', 'space'])
