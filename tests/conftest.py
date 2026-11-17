"""Profile Hypothesis: lokalnie szybki (domyślny), w CI dokładniejszy (HYPOTHESIS_PROFILE=ci)."""
import os

from hypothesis import HealthCheck, settings

settings.register_profile("dev", max_examples=60, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow])
settings.register_profile("ci", max_examples=300, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow])
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))
