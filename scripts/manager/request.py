import json
import logging
import random
import warnings
from hashlib import sha1
from pathlib import Path
from time import sleep

import requests
from docx import Document
from manager.cache import CacheManager, CacheType

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

logger = logging.getLogger(__name__)

BASE_URL = "https://flk.npc.gov.cn"

REQUEST_HEADER = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Referer": "https://flk.npc.gov.cn/fl.html",
    "Origin": "https://flk.npc.gov.cn",
}


class RequestManager(object):
    def __init__(self) -> None:
        self.cache = CacheManager()
        self.flfgCodeId = []   # 法律法规分类 codeId 列表，空表示全部
        self.zdjgCodeId = []   # 制定机关 codeId 列表，空表示全部
        self.searchContent = ""
        self.sxx = []          # 效力状态过滤，空表示全部
        self._session = requests.Session()
        self._session.verify = False
        self._session.headers.update(REQUEST_HEADER)

    def getLawList(self, page=1):
        body = {
            "searchType": 2,
            "searchRange": 1,
            "searchContent": self.searchContent,
            "flfgCodeId": self.flfgCodeId,
            "zdjgCodeId": self.zdjgCodeId,
            "sxrq": [],
            "gbrq": [],
            "gbrqYear": [],
            "sxx": self.sxx,
            "orderByParam": {"order": "-1", "sort": ""},
            "pageNum": page,
            "pageSize": 100,
        }

        cache_key = sha1(json.dumps(body, sort_keys=True).encode()).hexdigest()

        if cache := self.cache.get(cache_key, CacheType.WebPage, "json"):
            return cache

        response = self._session.post(
            f"{BASE_URL}/law-search/search/list",
            json=body,
        )
        sleep(random.uniform(1, 3))
        logger.debug(f"requesting [{response.status_code}] page={page}")

        ret = response.json()
        self.cache.set(cache_key, CacheType.WebPage, ret, "json")
        return ret

    def get_law_detail(self, bbbs: str):
        if cache := self.cache.get(bbbs, CacheType.WebPage, "json"):
            return cache
        logger.debug(f"getting law detail {bbbs}")
        ret = self._session.get(
            f"{BASE_URL}/law-search/search/flfgDetails",
            params={"bbbs": bbbs},
        )
        sleep(random.uniform(1, 3))
        ret = ret.json()
        self.cache.set(bbbs, CacheType.WebPage, ret, "json")
        return ret

    def get_word(self, bbbs: str, title_or_output_path: Path) -> Document:
        title = title_or_output_path.name

        # 优先从缓存读取 docx
        ok, path = self.cache.is_exists(title, CacheType.WordDocument, "docx")

        if not ok:
            # 通过 download/pc 接口获取签名下载 URL
            logger.debug(f"getting signed download url for {bbbs}")
            r = self._session.get(
                f"{BASE_URL}/law-search/download/pc",
                params={"format": "docx", "bbbs": bbbs, "fileId": ""},
            )
            sleep(random.uniform(1, 3))
            data = r.json()
            if data.get("code") != 200:
                logger.error(f"Failed to get download URL for {bbbs}: {data}")
                return None

            download_url = data["data"]["url"]

            _, download_path = self.cache.is_exists(
                title, CacheType.WordDocument, "docx", create_if_not_exists=True
            )

            try:
                file_resp = self._session.get(download_url, timeout=30)
                sleep(random.uniform(1, 3))
                with open(download_path, "wb") as f:
                    f.write(file_resp.content)
                path = download_path
            except Exception as e:
                logger.error(f"Failed to download {bbbs}: {e}")
                return None

        if not path or not path.exists():
            logger.error(f"File not found at path: {path}")
            return None

        with open(path, "rb") as f:
            try:
                return Document(f)
            except Exception as e:
                logger.error(f"Failed to open document {path}: {e}")
                return None
