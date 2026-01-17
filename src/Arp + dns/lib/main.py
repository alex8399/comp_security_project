from console import Console
import sys


def main():
    console = Console()
    console.execute(sys.argv[1:])


if __name__ == "__main__":
    main()
