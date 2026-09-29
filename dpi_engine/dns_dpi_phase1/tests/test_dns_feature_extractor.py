from dpi_engine.dns.dns_feature_extractor import (
    FEATURE_ORDER,
    build_dns_features,
)


def test_use_typekit_features():
    features = build_dns_features(
        domain="use.typekit.net.",
        packet_lengths=[75, 183],
        duration=0.13126,
        src_port=63064,
        sending_bytes=75,
        ttl_values=[26, 60, 60, 10552],
        answer_record_types=[5, 5, 1, 1],
    )

    assert features["dns_domain_name_length"] == 16
    assert features["dns_subdomain_name_length"] == 3

    assert features["numerical_percentage"] == 0.0

    assert round(features["character_entropy"], 6) == 3.108459

    assert round(
        features["conv_freq_vowels_consonants"],
        6,
    ) == 0.6

    assert features["min_packets_len"] == 75
    assert features["max_packets_len"] == 183

    assert features["mean_packets_len"] == 129.0

    assert features["variance_packets_len"] == 2916.0

    assert features["standard_deviation_packets_len"] == 54.0

    assert round(
        features["coefficient_of_variation_packets_len"],
        6,
    ) == round(54 / 129, 6)

    assert features["total_bytes"] == 258

    assert round(
        features["packets_rate"],
        6,
    ) == round(2 / 0.13126, 6)

    assert round(
        features["packets_len_rate"],
        6,
    ) == round(258 / 0.13126, 6)

    assert features["ttl_values_min"] == 26
    assert features["ttl_values_max"] == 10552
    assert features["ttl_values_mean"] == 2674.5
    assert features["ttl_values_mode"] == 60.0
    assert features["ttl_values_median"] == 60.0

    # ALFlowLyzer counts A-record RR types.
    # 1 = A, so [5, 5, 1, 1] -> 2
    assert features["distinct_A_records"] == 2

    assert features["src_port"] == 63064
    assert features["sending_bytes"] == 75


def test_feature_order():
    features = build_dns_features(
        domain="example.com.",
        packet_lengths=[50, 100],
        duration=1.0,
        src_port=50000,
        sending_bytes=50,
        ttl_values=[60],
        answer_record_types=[1],
    )

    assert list(features.keys()) == FEATURE_ORDER


def test_distinct_a_records():
    features = build_dns_features(
        domain="example.com.",
        packet_lengths=[50, 100],
        duration=1.0,
        src_port=50000,
        sending_bytes=50,
        ttl_values=[60],
        answer_record_types=[
            1,
            1,
            5,
        ],
    )

    # ALFlowLyzer does NOT count unique A-record IP addresses.
    # It counts DNS answer records whose type is A (type 1).
    assert features["distinct_A_records"] == 2


def test_no_a_records():
    features = build_dns_features(
        domain="example.com.",
        packet_lengths=[50, 100],
        duration=1.0,
        src_port=50000,
        sending_bytes=50,
        ttl_values=[60],
        answer_record_types=[
            5,
            5,
            28,
        ],
    )

    assert features["distinct_A_records"] == 0


def test_multiple_a_records_same_ip_semantics():
    features = build_dns_features(
        domain="example.com.",
        packet_lengths=[50, 100],
        duration=1.0,
        src_port=50000,
        sending_bytes=50,
        ttl_values=[60],
        answer_record_types=[
            1,
            1,
            1,
        ],
    )

    # Three A records means 3, regardless of whether their IP
    # addresses are the same or different.
    assert features["distinct_A_records"] == 3