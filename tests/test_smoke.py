import seatbelt
from seatbelt.cli import main


def test_package_imports_and_cli_runs():
    assert seatbelt.__version__
    assert main([]) == 0
