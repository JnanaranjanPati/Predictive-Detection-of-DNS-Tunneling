import pandas as pd
from dpi_engine.dns.dns_feature_extractor import (
    domain_length,
    subdomain_length,
    numerical_percentage,
    character_entropy,
    alternating_vowel_consonant_frequency,
)

CSV_PATH = r"..\..\data\raw\benign.csv"

df = pd.read_csv(CSV_PATH, nrows=20)

print("\nComparing DNS lexical features\n")
print("=" * 90)

for i, row in df.iterrows():
    domain = str(row["dns_domain_name"])

    generated = {
        "dns_domain_name_length": domain_length(domain),
        "dns_subdomain_name_length": subdomain_length(domain),
        "numerical_percentage": numerical_percentage(domain),
        "character_entropy": character_entropy(domain),
        "conv_freq_vowels_consonants":
            alternating_vowel_consonant_frequency(domain),
    }

    print(f"\nRow {i + 1}: {domain}")

    for feature, generated_value in generated.items():
        dataset_value = row[feature]

        print(
            f"{feature:35s} "
            f"dataset={dataset_value:<12} "
            f"generated={generated_value:<12.6f} "
            f"diff={abs(float(dataset_value) - generated_value):.6f}"
        )