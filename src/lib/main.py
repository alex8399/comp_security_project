from console import Console
import logging
import sys


logging.basicConfig(level=logging.INFO)


def main():
    console = Console()
    console.execute(sys.argv[1:])


if __name__ == "__main__":
    main()
