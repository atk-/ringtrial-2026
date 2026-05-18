from pathlib import Path

import re
import scrapy


def clean(x):
    return re.sub('[^a-zA-Z0-9]', '', x)


class EntertainmentSpider(scrapy.Spider):
    name = "entertainment"

    async def start(self):
        urls = [
            # "https://en.wikipedia.org/wiki/Teenage_Mutant_Ninja_Turtles",
            # "https://en.wikipedia.org/wiki/Teenage_Mutant_Ninja_Turtles_(1987_TV_series)",
            # "https://en.wikipedia.org/wiki/Transformers:_Generation_1",
            # "https://en.wikipedia.org/wiki/Lucky_Luke",
            # "https://en.wikipedia.org/wiki/ThunderCats",
            # "https://en.wikipedia.org/wiki/He-Man",
            # "https://en.wikipedia.org/wiki/Scooby-Doo",
            # "https://de.wikipedia.org/wiki/Lucky_Luke",
            "https://en.wikipedia.org/wiki/Asterix",

        ]

        for url in urls:
            yield scrapy.Request(url=url, callback=self.parse)

    def parse(self, response):
        results = set()
        data = response.css('div.mw-content-ltr')[0]

        for link in data.css('a::text'):
            results.add(link.get().replace(' ', ''))
            results.update(set(map(clean, link.get().split(' '))))

        for p in data.css('p::text'):
            results.update(set(map(clean, p.get().split(' '))))


        open('ent-words.txt', 'a').write('\n'.join(sorted(results)))


