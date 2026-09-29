"""
DNS feature extraction compatible with the DNS tunneling ML dataset.

The extractor converts an aggregated DNS flow into the feature vector
expected by the existing XGBoost model.

The feature definitions are based on the DNS tunneling dataset and
the ALFlowLyzer source used to generate that dataset.

Expected model features:
    duration
    min_packets_len
    ttl_values_mode
    max_packets_len
    distinct_A_records
    src_port
    variance_packets_len
    conv_freq_vowels_consonants
    total_bytes
    mean_packets_len
    dns_domain_name_length
    ttl_values_min
    character_entropy
    ttl_values_mean
    ttl_values_max
    numerical_percentage
    coefficient_of_variation_packets_len
    packets_len_rate
    ttl_values_median
    packets_rate
    sending_bytes
    dns_subdomain_name_length
    standard_deviation_packets_len
"""

from __future__ import annotations

import math
from collections import Counter
from statistics import mean, median
from typing import Iterable, Optional

from scipy import stats


# IMPORTANT:
# This order matches configs/selected_features.json and
# models/scaler.pkl.
FEATURE_ORDER = [
    "duration",
    "min_packets_len",
    "ttl_values_mode",
    "max_packets_len",
    "distinct_A_records",
    "src_port",
    "variance_packets_len",
    "conv_freq_vowels_consonants",
    "total_bytes",
    "mean_packets_len",
    "dns_domain_name_length",
    "ttl_values_min",
    "character_entropy",
    "ttl_values_mean",
    "ttl_values_max",
    "numerical_percentage",
    "coefficient_of_variation_packets_len",
    "packets_len_rate",
    "ttl_values_median",
    "packets_rate",
    "sending_bytes",
    "dns_subdomain_name_length",
    "standard_deviation_packets_len",
]


VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def _safe_domain(domain: Optional[str]) -> str:
    """
    Normalize a DNS domain while preserving the trailing dot.

    The dataset stores domains such as:

        use.typekit.net.

    The trailing dot is therefore retained when calculating
    domain-level features.
    """
    if domain is None:
        return ""

    return str(domain).strip().lower()


def domain_length(domain: str) -> int:
    """
    Return the complete DNS domain length.

    The dataset includes the trailing '.' in the length.
    """
    return len(domain)


def subdomain_length(domain: str) -> int:
    """
    Return the length of the first/left-most DNS label.

    Examples:
        use.typekit.net. -> 3
        www.example.com. -> 3
    """
    without_trailing_dot = domain.rstrip(".")

    if not without_trailing_dot:
        return 0

    first_label = without_trailing_dot.split(".", 1)[0]

    return len(first_label)


def numerical_percentage(domain: str) -> float:
    """
    Calculate the percentage of numeric characters.

    Formula:

        number of digits / complete domain length

    Example:

        4gamers.co.th. -> 1 / 14
    """
    length = len(domain)

    if length == 0:
        return 0.0

    numeric_count = sum(
        character.isdigit()
        for character in domain
    )

    return numeric_count / length


def character_entropy(domain: str) -> float:
    """
    Calculate Shannon entropy of characters in the complete DNS domain.

    H(X) = -sum(p(x) * log2(p(x)))
    """
    if not domain:
        return 0.0

    counts = Counter(domain)
    length = len(domain)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def alternating_vowel_consonant_frequency(
    domain: str,
) -> float:
    """
    Reproduce ALFlowLyzer's
    ConvFreqVowelsConsonants feature.

    ALFlowLyzer:

    1. Uses a fixed lowercase vowel set:
           a, e, i, o, u

    2. Uses a fixed lowercase consonant set:
           b,c,d,f,g,h,j,k,l,m,n,p,q,r,s,t,v,w,x,y,z

    3. Checks adjacent vowel/consonant pairs.

    4. Handles '.' specially by checking across the dot.

       Example:

           e.t

       can be treated as:

           e -> t

    5. When a dot is skipped, the denominator is reduced by one.

    This implementation intentionally follows the ALFlowLyzer
    implementation rather than using a generic vowel/consonant
    transition calculation.
    """
    domain = _safe_domain(domain)

    if not domain:
        return 0.0

    freq_count = 0
    total_count = len(domain)

    for i in range(len(domain) - 2):

        # Normal adjacent consonant -> vowel
        if (
            domain[i] in CONSONANTS
            and domain[i + 1] in VOWELS
        ):
            freq_count += 1

        # Normal adjacent vowel -> consonant
        elif (
            domain[i] in VOWELS
            and domain[i + 1] in CONSONANTS
        ):
            freq_count += 1

        # ALFlowLyzer's special handling of '.'
        elif (
            domain[i + 1] == "."
            and i < len(domain) - 3
        ):

            # consonant . vowel
            if (
                domain[i] in CONSONANTS
                and domain[i + 2] in VOWELS
            ):
                freq_count += 1
                total_count -= 1

            # vowel . consonant
            elif (
                domain[i] in VOWELS
                and domain[i + 2] in CONSONANTS
            ):
                freq_count += 1
                total_count -= 1

    return freq_count / total_count


def packet_statistics(
    packet_lengths: Iterable[float],
) -> dict[str, float]:
    """
    Calculate packet-length statistics used by the ML model.

    Returns:

        min_packets_len
        max_packets_len
        mean_packets_len
        variance_packets_len
        standard_deviation_packets_len
        coefficient_of_variation_packets_len
        total_bytes

    The dataset/ALFlowLyzer uses population variance and population
    standard deviation for packet lengths.
    """
    lengths = [
        float(length)
        for length in packet_lengths
    ]

    if not lengths:
        return {
            "min_packets_len": 0.0,
            "max_packets_len": 0.0,
            "mean_packets_len": 0.0,
            "variance_packets_len": 0.0,
            "standard_deviation_packets_len": 0.0,
            "coefficient_of_variation_packets_len": 0.0,
            "total_bytes": 0.0,
        }

    packet_mean = mean(lengths)

    # Population variance.
    variance = mean(
        (packet_length - packet_mean) ** 2
        for packet_length in lengths
    )

    standard_deviation = math.sqrt(variance)

    if packet_mean == 0:
        coefficient_of_variation = 0.0
    else:
        coefficient_of_variation = (
            standard_deviation / packet_mean
        )

    return {
        "min_packets_len": min(lengths),
        "max_packets_len": max(lengths),
        "mean_packets_len": packet_mean,
        "variance_packets_len": variance,
        "standard_deviation_packets_len": standard_deviation,
        "coefficient_of_variation_packets_len": (
            coefficient_of_variation
        ),
        "total_bytes": sum(lengths),
    }


def ttl_statistics(
    ttl_values: Iterable[float],
) -> dict[str, float]:
    """
    Calculate TTL statistics used by the ML model.

    TTL values are NOT deduplicated.

    Therefore:

        [26, 60, 60, 10552]

    remains four observations.

    Statistics:

        min
        max
        mean
        mode
        median
    """
    ttls = [
        float(ttl)
        for ttl in ttl_values
    ]

    if not ttls:
        return {
            "ttl_values_min": 0.0,
            "ttl_values_max": 0.0,
            "ttl_values_mean": 0.0,
            "ttl_values_mode": 0.0,
            "ttl_values_median": 0.0,
        }

    # ALFlowLyzer uses scipy.stats.mode().
    mode_value = float(
        stats.mode(ttls, keepdims=False).mode
    )

    return {
        "ttl_values_min": min(ttls),
        "ttl_values_max": max(ttls),
        "ttl_values_mean": mean(ttls),
        "ttl_values_mode": mode_value,
        "ttl_values_median": median(ttls),
    }


def distinct_a_records(
    answer_record_types: Iterable[int],
) -> int:
    """
    Reproduce ALFlowLyzer's distinct_A_records feature.

    Important:

    Despite the feature name, ALFlowLyzer does NOT count unique
    IPv4 addresses.

    It counts the number of DNS answer records whose RR type
    is A.

    DNS type code:

        A = 1

    Example:

        answer_record_types = [5, 5, 1, 1]

        result = 2
    """
    record_types = [
        int(record_type)
        for record_type in answer_record_types
    ]

    return record_types.count(1)


def build_dns_features(
    *,
    domain: str,
    packet_lengths: Iterable[float],
    duration: float,
    src_port: int,
    sending_bytes: float,
    ttl_values: Iterable[float],
    answer_record_types: Iterable[int],
) -> dict[str, float]:
    """
    Build the complete 23-feature dictionary expected by
    the existing XGBoost model.

    Parameters
    ----------
    domain:
        DNS query domain.

        Example:
            use.typekit.net.

    packet_lengths:
        Packet lengths belonging to the DNS flow.

    duration:
        DNS flow duration in seconds.

    src_port:
        Source/client port.

    sending_bytes:
        Bytes sent from the DNS client toward the DNS server.

    ttl_values:
        TTL values observed in DNS answer records.

    answer_record_types:
        DNS answer RR type codes.

        Example:
            [5, 5, 1, 1]

        where:
            5 = CNAME
            1 = A

    Returns
    -------
    dict[str, float]
        Dictionary containing exactly the 23 canonical
        XGBoost features.
    """

    domain = _safe_domain(domain)

    packet_lengths = list(packet_lengths)
    ttl_values = list(ttl_values)
    answer_record_types = list(answer_record_types)

    packet_stats = packet_statistics(
        packet_lengths
    )

    ttl_stats = ttl_statistics(
        ttl_values
    )

    total_bytes = packet_stats["total_bytes"]

    packet_count = len(packet_lengths)

    duration = float(duration)

    # ALFlowLyzer / dataset:
    #
    # packets_rate = packet count / duration
    # packets_len_rate = total bytes / duration
    #
    # Protect against division by zero.
    if duration > 0:
        packets_rate = packet_count / duration
        packets_len_rate = total_bytes / duration
    else:
        packets_rate = 0.0
        packets_len_rate = 0.0

    features = {
        "duration": duration,

        "min_packets_len": (
            packet_stats["min_packets_len"]
        ),

        "ttl_values_mode": (
            ttl_stats["ttl_values_mode"]
        ),

        "max_packets_len": (
            packet_stats["max_packets_len"]
        ),

        "distinct_A_records": (
            distinct_a_records(answer_record_types)
        ),

        "src_port": int(src_port),

        "variance_packets_len": (
            packet_stats["variance_packets_len"]
        ),

        "conv_freq_vowels_consonants": (
            alternating_vowel_consonant_frequency(
                domain
            )
        ),

        "total_bytes": total_bytes,

        "mean_packets_len": (
            packet_stats["mean_packets_len"]
        ),

        "dns_domain_name_length": (
            domain_length(domain)
        ),

        "ttl_values_min": (
            ttl_stats["ttl_values_min"]
        ),

        "character_entropy": (
            character_entropy(domain)
        ),

        "ttl_values_mean": (
            ttl_stats["ttl_values_mean"]
        ),

        "ttl_values_max": (
            ttl_stats["ttl_values_max"]
        ),

        "numerical_percentage": (
            numerical_percentage(domain)
        ),

        "coefficient_of_variation_packets_len": (
            packet_stats[
                "coefficient_of_variation_packets_len"
            ]
        ),

        "packets_len_rate": packets_len_rate,

        "ttl_values_median": (
            ttl_stats["ttl_values_median"]
        ),

        "packets_rate": packets_rate,

        "sending_bytes": float(sending_bytes),

        "dns_subdomain_name_length": (
            subdomain_length(domain)
        ),

        "standard_deviation_packets_len": (
            packet_stats[
                "standard_deviation_packets_len"
            ]
        ),
    }

    # Safety check:
    # The feature dictionary must contain exactly the
    # features expected by the scaler/model.
    if set(features) != set(FEATURE_ORDER):

        missing = set(FEATURE_ORDER) - set(features)
        extra = set(features) - set(FEATURE_ORDER)

        raise ValueError(
            f"Feature mismatch. "
            f"Missing={missing}, Extra={extra}"
        )

    return features


def build_feature_vector(
    *,
    domain: str,
    packet_lengths: Iterable[float],
    duration: float,
    src_port: int,
    sending_bytes: float,
    ttl_values: Iterable[float],
    answer_record_types: Iterable[int],
) -> list[float]:
    """
    Return feature values in the exact scaler/model input order.

    This is the function that will eventually feed:

        StandardScaler
              ↓
           XGBoost
    """

    features = build_dns_features(
        domain=domain,
        packet_lengths=packet_lengths,
        duration=duration,
        src_port=src_port,
        sending_bytes=sending_bytes,
        ttl_values=ttl_values,
        answer_record_types=answer_record_types,
    )

    return [
        features[name]
        for name in FEATURE_ORDER
    ]