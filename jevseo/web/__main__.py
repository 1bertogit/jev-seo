from __future__ import annotations

import argparse


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="python -m jevseo.web", description="Run the hosted Jev SEO audit service.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    import uvicorn

    from .app import create_app
    from .config import WebConfig

    uvicorn.run(create_app(WebConfig.from_env()), host=args.host, port=args.port, workers=1)


if __name__ == "__main__":
    main()
