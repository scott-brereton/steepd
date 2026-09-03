import steepd


def test_package_exposes_version():
    assert isinstance(steepd.__version__, str)
    assert steepd.__version__
