import re

INPUT_FILE = 'ent-words.txt'
OUTPUT_FILE = 'ent.txt'

res = set()

for w in open(INPUT_FILE, 'r'):
    w = w.strip()
    if not re.search('[\'.,"/()]', w):
        res.add(w)

out = open(OUTPUT_FILE, 'w')

for x in sorted(res):
    print(x, file=out)

out.close()

