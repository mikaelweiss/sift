import os
import sys
from datetime import datetime, timezone

appcast_path = sys.argv[1]
version = os.environ["APPCAST_VERSION"]
build = os.environ["APPCAST_BUILD"]
url = os.environ["APPCAST_URL"]
signature = os.environ["APPCAST_SIGNATURE"]
minimum_os = os.environ["APPCAST_MINIMUM_OS"]
pub_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %z")

item = f"""    <item>
      <title>Version {version}</title>
      <pubDate>{pub_date}</pubDate>
      <sparkle:version>{build}</sparkle:version>
      <sparkle:shortVersionString>{version}</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>{minimum_os}</sparkle:minimumSystemVersion>
      <sparkle:releaseNotesLink>https://github.com/mikaelweiss/sift/releases/tag/v{version}</sparkle:releaseNotesLink>
      <enclosure
        url="{url}"
        {signature}
        type="application/octet-stream"/>
    </item>"""

if os.path.exists(appcast_path):
    with open(appcast_path) as f:
        content = f.read()
    content = content.replace("  </channel>", item + "\n  </channel>")
else:
    content = f"""<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel>
    <title>Sift Updates</title>
    <link>https://sift.weisssolutions.org/</link>
    <description>Sift update feed.</description>
    <language>en</language>
{item}
  </channel>
</rss>
"""

with open(appcast_path, "w") as f:
    f.write(content)
