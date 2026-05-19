import argparse
import re

def clean_string(x):
    x = ''.join([t.capitalize() for t in x.strip().split(' ')])
    x = re.sub('[^a-zA-Z0-9 ]', '', x)
    return x


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('inputpath')
    parser.add_argument('outputpath')

    args = parser.parse_args()

    words = open(args.inputpath).read().split('\n')
    words = sorted(set(map(clean_string, words)))

    out = open(args.outputpath, 'w')

    for x in words:
        print(x, file=out)

    out.close()

