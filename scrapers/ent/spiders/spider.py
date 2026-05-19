from pathlib import Path

import re
import scrapy


def clean(x):
    if '(' in x:
        x = x[:x.find('(')]

    x = x.strip()

    return re.sub('[^a-zA-Z0-9 ]', '', x)


def eat_spaces(x):
    tokens = x.split(' ')
    return ''.join([t.capitalize() for t in tokens])


class AsterixSpider(scrapy.Spider):
    name = "asterix"
    result_file = 'res/asterix.txt'

    async def start(self):
        urls = [
            "https://en.wikipedia.org/wiki/List_of_Asterix_characters",
        ]

        for url in urls:
            yield scrapy.Request(url=url, callback=self.parse)

    def parse(self, response):
        results = set()
        names = response.xpath('//h3/text()').getall()
        names += response.xpath('//h4/text()').getall()

        names = sorted(map(eat_spaces, map(clean, names)))

        out = open(self.result_file, 'w')

        for n in names:
            print(n, file=out)

        out.close()


class TransformerSpider(scrapy.Spider):
    name = 'transformers'

    async def start(self):
        urls = [
            "https://en.wikipedia.org/wiki/List_of_The_Transformers_characters",
        ]

        for url in urls:
            yield scrapy.Request(url=url, callback=self.parse)

    def parse(self, response):
        results = set()

        cells = response.xpath('//tr/td[1][not(@colspan)][not(@class)]')

        for cell in cells:
            if cell.css('a'):
                results.update(cell.css('a::text').getall())
            else:
                results.update(cell.css('td::text').getall())

        results = sorted(set(map(eat_spaces, map(clean, results))))

        result_file = f'res/{self.name}.txt'
        out = open(result_file, 'w')

        for r in results:
            print(r, file=out)

        out.close()


class TurtlesSpider(scrapy.Spider):
    name = 'turtles'

    async def start(self):
        urls = [
            'https://en.wikipedia.org/wiki/List_of_Teenage_Mutant_Ninja_Turtles_characters'
        ]

        for url in urls:
            yield scrapy.Request(url=url, callback=self.parse)

    def parse(self, response):
        entries = response.css('div.mw-heading3').css('h3::text').getall()
        entries += response.css('div.mw-heading4').css('h4::text').getall()

        for e in entries:
            if ' and ' in e:
                entries.extend(e.split(' and '))

        results = sorted(set(map(eat_spaces, map(clean, entries))))

        result_file = f'res/{self.name}.txt'
        out = open(result_file, 'w')

        for r in results:
            print(r, file=out)

        out.close()


class ThundercatSpider(scrapy.Spider):
    name = 'thundercats'

    async def start(self):
        urls = [
            "https://en.wikipedia.org/wiki/List_of_ThunderCats_characters",
        ]

        for url in urls:
            yield scrapy.Request(url=url, callback=self.parse)

    def parse(self, response):
        entries = response.css('div.mw-heading3').css('h3::text').getall()
        entries += response.css('div.mw-heading4').css('h4::text').getall()
        entries += response.xpath('//ul/li/b/text()').getall()

        for e in entries:
            if ' and ' in e:
                entries.extend(e.split(' and '))

        results = sorted(set(map(eat_spaces, map(clean, entries))))

        result_file = f'res/{self.name}.txt'
        out = open(result_file, 'w')

        for r in results:
            print(r, file=out)

        out.close()


class HeManSpider(scrapy.Spider):
    name = 'heman'

    async def start(self):
        urls = [
            "https://en.wikipedia.org/wiki/List_of_He-Man_and_the_Masters_of_the_Universe_characters",
        ]

        for url in urls:
            yield scrapy.Request(url=url, callback=self.parse)

    def parse(self, response):
        entries = response.css('div.mw-heading3').css('h3::text').getall()
        entries += response.css('div.mw-heading4').css('h4::text').getall()
        entries += response.xpath('//ul/li/b/text()').getall()

        for e in entries:
            if ' and ' in e:
                entries.extend(e.split(' and '))
            if ' / ' in e:
                entries.extend(e.split(' / '))

        results = sorted(set(map(eat_spaces, map(clean, entries))))

        result_file = f'res/{self.name}.txt'
        out = open(result_file, 'w')

        for r in results:
            print(r, file=out)

        out.close()


class ScoobyDooSpider(scrapy.Spider):
    name = 'scoobydoo'

    async def start(self):
        urls = [
            "https://en.wikipedia.org/wiki/List_of_Scooby-Doo_characters",
        ]

        for url in urls:
            yield scrapy.Request(url=url, callback=self.parse)

    def parse(self, response):
        entries = response.css('div.mw-heading3').css('h3::text').getall()
        entries += response.css('div.mw-heading4').css('h4::text').getall()
        # entries += response.xpath('//ul/li/b/text()').getall()

        for e in entries:
            if ' and ' in e:
                entries.extend(e.split(' and '))
            if ' / ' in e:
                entries.extend(e.split(' / '))

        results = sorted(set(map(eat_spaces, map(clean, entries))))

        result_file = f'res/{self.name}.txt'
        out = open(result_file, 'w')

        for r in results:
            print(r, file=out)

        out.close()


### TEMPLATE
class Spider(scrapy.Spider):
    name = ''

    async def start(self):
        urls = [
        ]

        for url in urls:
            yield scrapy.Request(url=url, callback=self.parse)

    def parse(self, response):
        results = set()

        # ...

        results = sorted(set(map(eat_spaces, map(clean, results))))

        result_file = f'res/{self.name}.txt'
        out = open(result_file, 'w')

        for r in results:
            print(r, file=out)

        out.close()


###################################

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


