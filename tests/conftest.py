import pytest

# The tests must not depend on the machine they run on. CI runners (and developers) often set these; seatbelt reads them.
LEAKY = ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "SEATBELT_CONFIG", "SEATBELT_AUDIT_LOG", "SEATBELT_AUDIT", "SEATBELT_HEADLESS",
         "SEATBELT_PREVIEW", "KUBECONFIG", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "TF_WORKSPACE", "KUBE_CONTEXT", "APP_ENV",
         "NODE_ENV", "RAILS_ENV", "DJANGO_ENV", "ENVIRONMENT", "DATABASE_URL", "PGHOST", "PGDATABASE", "MYSQL_HOST", "REDIS_URL")


@pytest.fixture(autouse=True)
def hermetic_environment(monkeypatch):
    for name in LEAKY:
        monkeypatch.delenv(name, raising=False)
