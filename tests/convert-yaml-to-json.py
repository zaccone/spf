#!/usr/bin/python3

try:
    import yaml
except ImportError:
    raise SystemExit("Unable to load yaml module.")
import json
import sys

def main():
    filename = None
    try:
        filename = sys.argv[1]
    except IndexError as e:
        raise SystemExit("Usage: {0} <yaml file>".format(
            sys.argv[0]
        ))
    try:
        with open(filename, 'rb') as fh:
            yml = yaml.safe_load_all(fh)
            yml = list(yml)
            print(json.dumps(yml, indent=2))
    except IOError as e:
        raise SystemExit(e)



if __name__ == '__main__':
    main()


