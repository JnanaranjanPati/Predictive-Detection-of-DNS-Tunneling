from src.utils.paths import load_config

def get_network_features() -> list:
    """Returns the expected TTL, Packet, and Flow feature columns from config."""
    config = load_config("dataset")
    features = config["schema"]["features"]
    return features["ttl"] + features["packet"] + features["flow"]