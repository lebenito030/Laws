import logging
import os
import re
import sys
from hashlib import md5
from pathlib import Path
from time import time
from typing import Any, List

from common import LINE_RE, NUMBER_RE
from manager import CacheManager, RequestManager
from parsers import ContentParser, WordParser

logger = logging.getLogger("Law")
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter("%(asctime)s:%(levelname)s:%(message)s")

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

logger.addHandler(console_handler)


def find(f, arr: List[Any]) -> Any:
    for item in arr:
        if f(item):
            return item
    raise Exception("not found")


def isStartLine(line: str):
    for reg in LINE_RE:
        if re.match(reg, line):
            return True
    return False


class LawParser(object):
    def __init__(self) -> None:
        self.request = RequestManager()
        self.spec_title = None
        self.parser = WordParser()
        self.content_parser = ContentParser()
        self.cache = CacheManager()
        self.categories = []

    def is_bypassed_law(self, item) -> bool:
        title = item["title"].replace("中华人民共和国", "")
        if self.spec_title and title in self.spec_title:
            return False
        if re.search(r"的(决定|复函|批复|答复|批复)$", title):
            return True
        return False

    def _add_markers_to_filedata(self, filedata: List[str]) -> List[str]:
        new_ret = []
        open_levels = []  # stack to keep track of open sections/chapters
        article_open = False  # to track if an article is open

        # This regex will match "第X条"
        article_re = f"^第{NUMBER_RE}+条"

        for line in filedata:
            current_level = 0
            is_article = bool(re.match(article_re, line))

            if line.startswith('## '):
                current_level = 2
            elif line.startswith('### '):
                current_level = 3

            # If we are starting a new section/chapter
            if current_level > 0:
                if article_open:
                    new_ret.append('*小节结束*')
                    article_open = False

                # Close any open sections that are of a higher or equal level
                while open_levels and open_levels[-1] >= current_level:
                    level = open_levels.pop()
                    if level == 2 or level == 3:
                        new_ret.append('*章节结束*')

                # Now, open the new section/chapter
                open_levels.append(current_level)

            # If we are starting a new article
            if is_article:
                if article_open:
                    new_ret.append('*小节结束*')
                article_open = True

            new_ret.append(line)

        # Close any remaining open sections/articles at the end of the file
        if article_open:
            new_ret.append('*小节结束*')
        while open_levels:
            level = open_levels.pop()
            if level == 2 or level == 3:
                new_ret.append('*章节结束*')

        return new_ret

    def parse_law(self, item) -> bool:
        detail = self.request.get_law_detail(item["bbbs"])
        if detail.get("code") != 200:
            logger.error(f"get detail failed for {item['title']}: {detail}")
            return False
        result = detail["data"]
        title = result["title"]
        level = Path(result["flxz"])

        output_path = level / self.__get_law_output_path(title, item.get("gbrq", ""))
        if (self.cache.OUTPUT_PATH / output_path).exists():
            logger.debug(f"skip existing {title}")
            return False

        logger.debug(f"parsing {title}")

        if not result.get("ossFile", {}).get("ossWordPath"):
            logger.warning(f"no word file for {title}")
            return False

        ret = self.parser.parse(result, {"bbbs": item["bbbs"]})
        if not ret:
            logger.error(f"parsing {title} error")
            return False
        _, desc, content = ret

        filedata = self.content_parser.parse(result, title, desc, content)
        if not filedata:
            return False

        filedata = self._add_markers_to_filedata(filedata)

        logger.debug(f"parsing {title} success")
        self.cache.write_law(output_path, filedata)
        return True

    def parse_file(self, file_path, publish_at=None):
        result = {}
        with open(file_path, "r") as f:
            data = list(filter(lambda x: x, map(
                lambda x: x.strip(), f.readlines())))
        title = data[0]
        filedata = self.content_parser.parse(result, title, data[1], data[2:])
        if not filedata:
            return

        filedata = self._add_markers_to_filedata(filedata)

        output_path = self.__get_law_output_path(title, publish_at)
        logger.debug(f"parsing {title} success")
        self.cache.write_law(output_path, filedata)

    def get_file_hash(self, title, publish_at=None) -> str:
        _hash = md5()
        _hash.update(title.encode("utf8"))
        if publish_at:
            _hash.update(publish_at.encode("utf8"))
        return _hash.digest().hex()[0:8]

    def __get_law_output_path(self, title, publish_at: str) -> Path:
        title = title.replace("中华人民共和国", "")
        ret = Path(".")
        for category in self.categories:
            if title in category["title"]:
                ret = ret / category["category"]
                break
        # hash_hex = self.get_file_hash(title, publish_at)
        if publish_at:
            output_name = f"{title}({publish_at}).md"
        else:
            output_name = f"{title}.md"
        return ret / output_name

    def lawList(self):
        for i in range(1, 60):
            ret = self.request.getLawList(i)
            arr = ret.get("rows", [])
            if len(arr) == 0:
                break
            yield from arr

    def run(self):
        last_update_time = time()
        page = 1
        while True:
            logger.info(f"page is {page}")
            if time() - last_update_time > 5:
                logger.info("No new laws found in 5 seconds, exiting.")
                break
            ret = self.request.getLawList(page)
            arr = ret.get("rows", [])
            if len(arr) == 0:
                break
            for item in arr:
                if self.is_bypassed_law(item):
                    continue
                if self.parse_law(item):
                    last_update_time = time()
                if self.spec_title is not None:
                    exit(1)
            page += 1

    def remove_duplicates(self):
        p = self.cache.OUTPUT_PATH
        lookup = Path("../")
        for file_path in p.glob("*.md"):
            lookup_files = lookup.glob(f"**/**/{file_path.name}")
            lookup_files = filter(
                lambda x: "scripts" not in x.parts, lookup_files)
            lookup_files = list(lookup_files)
            if len(lookup_files) > 0:
                os.remove(file_path)
                print(f"remove {file_path}")


def main():
    req = LawParser()
    args = sys.argv[1:]
    if args:
        req.parse_file(args[0], args[1] if len(args) > 1 else None)
        return
    # 过滤示例（注释掉表示抓取全部）：
    # --- flfgCodeId（法律法规分类）---
    # 全部国家法律法规（不含地方）:
    req.request.flfgCodeId += [100,101,102,110,120,130,140,150,155,160,170,180,190,195,200,201,210,215,220,320,330,340,350]
    req.request.flfgCodeId += [110, 120, 130, 140, 150, 155, 160, 170]  # 全部法律
    req.request.flfgCodeId += [210]          # 行政法规
    req.request.flfgCodeId += [320, 330, 340]  # 司法解释
    req.request.flfgCodeId += [230, 300, 310]  # 地方法规（含废止决定）
    # --- zdjgCodeId（制定机关）---
    # 90=全国人大, 100=全国人大常委会, 110=全国人大各委, 120=国务院,
    # 130=国家监察委, 140=最高人民法院, 150=最高人民检察院
    # 380=重庆市人大, 其他地方人大见网页过滤器
    # --- 重庆地方法规示例 ---
    req.request.flfgCodeId += [230, 300, 310]
    req.request.zdjgCodeId = [380]
    # req.request.searchContent = "消防法"    # 关键词搜索
    # req.spec_title = "反有组织犯罪法"
    try:
        req.run()
    except KeyboardInterrupt:
        logger.info("keyboard interrupt")


if __name__ == "__main__":
    main()
