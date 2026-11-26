import os
from pathlib import Path
from urllib.parse import SplitResult, quote, urlsplit, urlunsplit

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder


class DoodUploader:
    SERVER_API = "https://doodapi.co/api/upload/server"

    def __init__(self, api_key: str, timeout: int = 3600):
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("API Key 不能为空")
        if timeout <= 0:
            raise ValueError("timeout 必须大于 0")
        self.api_key = api_key.strip()
        self.timeout = timeout

    @staticmethod
    def _request_json(method: str, url: str, **kwargs) -> dict:
        try:
            with requests.request(method, url, **kwargs) as response:
                if not 200 <= response.status_code < 300:
                    raise RuntimeError(f"HTTP 请求失败：{response.status_code}")
                result = response.json()
        except requests.exceptions.Timeout:
            raise RuntimeError("请求超时，请检查上传状态后再重试") from None
        except requests.exceptions.JSONDecodeError:
            raise RuntimeError("服务器返回的内容不是有效 JSON") from None
        except requests.exceptions.RequestException:
            raise RuntimeError("网络请求失败，请检查网络连接") from None

        if not isinstance(result, dict):
            raise RuntimeError("API 返回格式异常")
        if result.get("status") != 200:
            raise RuntimeError(f"API 请求失败：{result.get('msg', '未知错误')}")
        return result

    def get_upload_server(self) -> str:
        """获取本次上传使用的服务器地址。"""
        response = self._request_json(
            "GET", self.SERVER_API,
            params={"key": self.api_key},
            timeout=(15, 30),
        )
        server = response.get("result")
        if not isinstance(server, str):
            raise RuntimeError("未获取到有效的上传服务器地址")
        parts: SplitResult = urlsplit(server, scheme="")
        if parts.scheme != "https" or not parts.hostname:
            raise RuntimeError("上传服务器地址无效或不是 HTTPS")
        return server

    def upload(self, file_path: str | Path) -> dict:
        """上传一个本地 MP4 文件，返回该视频的完整结果字典。"""
        path = Path(file_path).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"文件不存在：{path}")
        if path.suffix.lower() != ".mp4":
            raise ValueError("仅支持 MP4 文件")
        if path.stat().st_size == 0:
            raise ValueError("不能上传空文件")

        server: SplitResult = urlsplit(self.get_upload_server(), scheme="")
        key = quote(self.api_key, safe="")
        query = f"{server.query}&{key}" if server.query else key
        upload_url = urlunsplit((server.scheme, server.netloc, server.path, query, ""))

        with path.open("rb") as video:
            multipart = MultipartEncoder(fields={
                "api_key": self.api_key,
                "file": (path.name, video, "video/mp4"),
            })
            response = self._request_json(
                "POST", upload_url,
                data=multipart,
                headers={"Content-Type": multipart.content_type},
                timeout=(15, self.timeout),
                allow_redirects=False,
            )

        results = response.get("result")
        if not isinstance(results, list) or not results:
            raise RuntimeError("上传接口未返回视频信息")
        result = results[0]
        if not isinstance(result, dict):
            raise RuntimeError("视频返回格式异常")
        if result.get("status") != 200 or not result.get("filecode"):
            raise RuntimeError(f"视频上传失败：{result.get('msg', '缺少有效视频结果')}")
        return result




uploader = DoodUploader(api_key=os.environ["DOOD_API_KEY"])

try:
    result = uploader.upload("/Users/kama/Movies/下载中/Google下载S2/【电话系列】电话那头男友以为是文爱 A片 - 91视频 色情视频 成人视频 91porn.mp4")
    filecode = result.get("filecode")
    video_url = result.get("protected_embed")
    cover_url = result.get("splash_img")
    print("上传成功：", result)
    print("视频编号：", filecode)
    print("播放地址：", video_url)
    print("封面地址：", cover_url)

except Exception as e:
    print("上传失败：", str(e))
