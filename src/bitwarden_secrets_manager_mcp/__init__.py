def main() -> None:
    from .server import main as server_main

    server_main()


__all__ = ["main"]
