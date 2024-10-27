import argparse
from constant import VT_API
from analyze_lnk import LNKAnalyzer


def main():
    parser = argparse.ArgumentParser(description='LNK File Analyzer')
    parser.add_argument('lnk_path', help='Path to the LNK file')
    parser.add_argument('--vt-api-key', help='VirusTotal API key')
    args = parser.parse_args()

    analyzer = LNKAnalyzer(args.lnk_path, VT_API)
    analyzer.analyze()

if __name__ == "__main__":
    main()