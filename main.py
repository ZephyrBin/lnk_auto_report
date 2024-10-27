import argparse
from constant import VT_API
from analyze_lnk import LNKAnalyzer
#"pip install pywin32 requests jinja2 matplotlib numpy" needed


def main():
    parser = argparse.ArgumentParser(description='LNK File Analyzer')
    parser.add_argument('lnk_path', help='Path to the LNK file')
    args = parser.parse_args()

    analyzer = LNKAnalyzer(args.lnk_path, VT_API)
    analyzer.analyze()

if __name__ == "__main__":
    main()