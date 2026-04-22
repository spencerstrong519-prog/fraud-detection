import pytest
from risk_rules import label_risk, score_transaction


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_tx(**overrides):
    """Clean-profile transaction: every signal at its lowest-risk value."""
    tx = {
        "device_risk_score": 5,
        "is_international": 0,
        "amount_usd": 10.0,
        "velocity_24h": 1,
        "failed_logins_24h": 0,
        "prior_chargebacks": 0,
    }
    tx.update(overrides)
    return tx


# ---------------------------------------------------------------------------
# label_risk
# ---------------------------------------------------------------------------

def test_label_risk_thresholds():
    assert label_risk(10) == "low"
    assert label_risk(29) == "low"
    assert label_risk(30) == "medium"
    assert label_risk(59) == "medium"
    assert label_risk(60) == "high"
    assert label_risk(100) == "high"


# ---------------------------------------------------------------------------
# Individual signal tests — each isolates one variable against the base profile
# ---------------------------------------------------------------------------

def test_clean_profile_scores_low():
    assert score_transaction(_base_tx()) == 0


def test_large_amount_adds_risk():
    assert score_transaction(_base_tx(amount_usd=1200)) >= 25


def test_mid_amount_adds_risk():
    score_low = score_transaction(_base_tx(amount_usd=100))
    score_mid = score_transaction(_base_tx(amount_usd=750))
    assert score_mid > score_low


def test_high_device_risk_increases_score():
    """A device_risk_score >= 70 must raise suspicion, not lower it."""
    score_clean = score_transaction(_base_tx(device_risk_score=5))
    score_risky = score_transaction(_base_tx(device_risk_score=75))
    assert score_risky > score_clean


def test_medium_device_risk_increases_score():
    score_clean = score_transaction(_base_tx(device_risk_score=5))
    score_medium = score_transaction(_base_tx(device_risk_score=50))
    assert score_medium > score_clean


def test_high_device_risk_scores_higher_than_medium_device_risk():
    score_medium = score_transaction(_base_tx(device_risk_score=50))
    score_high = score_transaction(_base_tx(device_risk_score=75))
    assert score_high > score_medium


def test_international_transaction_increases_score():
    """International flag must add risk, not subtract it."""
    score_domestic = score_transaction(_base_tx(is_international=0))
    score_intl = score_transaction(_base_tx(is_international=1))
    assert score_intl > score_domestic


def test_high_velocity_increases_score():
    """Six or more transactions in 24h is a red flag, not a green one."""
    score_low_velocity = score_transaction(_base_tx(velocity_24h=1))
    score_high_velocity = score_transaction(_base_tx(velocity_24h=8))
    assert score_high_velocity > score_low_velocity


def test_mid_velocity_increases_score():
    score_low = score_transaction(_base_tx(velocity_24h=1))
    score_mid = score_transaction(_base_tx(velocity_24h=4))
    assert score_mid > score_low


def test_high_velocity_scores_higher_than_mid_velocity():
    score_mid = score_transaction(_base_tx(velocity_24h=4))
    score_high = score_transaction(_base_tx(velocity_24h=8))
    assert score_high > score_mid


def test_high_failed_logins_increases_score():
    score_none = score_transaction(_base_tx(failed_logins_24h=0))
    score_high = score_transaction(_base_tx(failed_logins_24h=6))
    assert score_high > score_none


def test_prior_chargebacks_increase_score():
    """Accounts with prior chargebacks must score higher, not lower."""
    score_clean = score_transaction(_base_tx(prior_chargebacks=0))
    score_one_cb = score_transaction(_base_tx(prior_chargebacks=1))
    score_two_cb = score_transaction(_base_tx(prior_chargebacks=2))
    assert score_one_cb > score_clean
    assert score_two_cb > score_one_cb


# ---------------------------------------------------------------------------
# Score clamping
# ---------------------------------------------------------------------------

def test_score_cannot_go_below_zero():
    # Minimum possible profile — score must not be negative
    assert score_transaction(_base_tx()) >= 0


def test_score_cannot_exceed_100():
    # Maximum-risk profile — all signals at highest tier
    tx = _base_tx(
        device_risk_score=85,
        is_international=1,
        amount_usd=1500,
        velocity_24h=10,
        failed_logins_24h=6,
        prior_chargebacks=3,
    )
    assert score_transaction(tx) <= 100


# ---------------------------------------------------------------------------
# Combined / integration-style tests
# ---------------------------------------------------------------------------

def test_fraud_profile_scores_high():
    """A transaction matching all high-risk signals must reach the high tier."""
    tx = _base_tx(
        device_risk_score=85,
        is_international=1,
        amount_usd=1500,
        velocity_24h=8,
        failed_logins_24h=6,
        prior_chargebacks=2,
    )
    assert label_risk(score_transaction(tx)) == "high"


def test_known_fraud_transactions_score_medium_or_high():
    """
    The 8 confirmed chargebacks from chargebacks.csv must not score low.
    Signal values taken directly from transactions.csv and accounts.csv.
    """
    known_fraud_txs = [
        # (device_risk, is_intl, amount, velocity, failed_logins, prior_cb)
        (81, 1, 1250.00, 6, 5, 0),   # 50003 — Mia Chen
        (77, 1,  399.99, 7, 6, 3),   # 50006 — Ethan Brown
        (68, 1,  620.00, 5, 3, 0),   # 50008 — Mason Wilson
        (85, 1, 1400.00, 8, 7, 1),   # 50011 — Harper Allen
        (79, 1,  150.00, 7, 5, 0),   # 50013 — Mia Chen
        (72, 1,   49.99, 9, 7, 3),   # 50014 — Ethan Brown
        (71, 1,  910.00, 6, 4, 0),   # 50015 — Mason Wilson
        (83, 1,   75.00,10, 8, 1),   # 50019 — Harper Allen
    ]
    for device_risk, is_intl, amount, velocity, failed_logins, prior_cb in known_fraud_txs:
        tx = _base_tx(
            device_risk_score=device_risk,
            is_international=is_intl,
            amount_usd=amount,
            velocity_24h=velocity,
            failed_logins_24h=failed_logins,
            prior_chargebacks=prior_cb,
        )
        label = label_risk(score_transaction(tx))
        assert label in ("medium", "high"), (
            f"Known fraud tx (device={device_risk}, intl={is_intl}, "
            f"amount={amount}) scored '{label}' — expected medium or high"
        )


def test_clean_transactions_do_not_score_high():
    """
    Transactions with no risk signals must not reach the high tier.
    """
    clean_txs = [
        # (device_risk, is_intl, amount, velocity, failed_logins, prior_cb)
        ( 8, 0,  45.20, 1, 0, 0),   # 50001 — Ava Patel
        (12, 0,  14.99, 1, 0, 2),   # 50004 — Noah Davis
        ( 6, 0,  18.40, 1, 0, 2),   # 50009 — Amelia Martinez
        (10, 0,  64.50, 1, 0, 0),   # 50012 — James Young
        ( 9, 0,  35.00, 1, 0, 1),   # 50016 — Liam Johnson
        (15, 0, 120.00, 1, 0, 0),   # 50020 — Ava Patel
    ]
    for device_risk, is_intl, amount, velocity, failed_logins, prior_cb in clean_txs:
        tx = _base_tx(
            device_risk_score=device_risk,
            is_international=is_intl,
            amount_usd=amount,
            velocity_24h=velocity,
            failed_logins_24h=failed_logins,
            prior_chargebacks=prior_cb,
        )
        label = label_risk(score_transaction(tx))
        assert label != "high", (
            f"Clean tx (device={device_risk}, amount={amount}) "
            f"scored '{label}' — should not be high"
        )
