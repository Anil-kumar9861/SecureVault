import os

from dotenv import load_dotenv

from securevault.exceptions import ConfigError


def get_db_settings(dbname=None) -> dict:
    load_dotenv()

    password = os.getenv("DB_PASSWORD")

    if not password :
        raise ConfigError("DB_PASSWORD is not set")

    database_name = dbname or os.getenv("DB_NAME")

    if not database_name:
        raise ConfigError("DB_NAME is not set")

    return{
        "host" : os.getenv("DB_HOST", "localhost"),
        "port" : int(os.getenv("DB_PORT","5432")),
        "dbname":database_name,
        "user"  :os.getenv("DB_USER","postgres"),
        "password":password,
    }
