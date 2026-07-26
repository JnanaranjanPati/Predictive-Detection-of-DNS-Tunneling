from src.utils.paths import load_config

def get_dns_and_lexical_features() -> list:
    """Returns the expected DNS and Lexical feature columns from config."""
    config = load_config("dataset")
    return config["schema"]["features"]["dns"] + config["schema"]["features"]["lexical"]