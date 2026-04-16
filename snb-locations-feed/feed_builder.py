#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import html
import json
import re
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable


BASE_URL = "https://www.sevnb.ru"
CITIES = ["Сыктывкар", "Ухта", "Сосногорск", "Усинск", "Москва"]
USER_AGENT = "SNBLocationsFeed/1.0 (+https://www.sevnb.ru)"


@dataclass(slots=True)
class LocationRecord:
    location_type: str
    city: str
    address: str
    latitude: float
    longitude: float
    hours: str
    phone: str
    source_url: str
    fetched_at: str


def fetch_json(endpoint: str, city: str) -> list[dict]:
    query = urllib.parse.urlencode({"city": city})
    url = f"{BASE_URL}/{endpoint}?{query}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read().decode("utf-8")
    data = json.loads(payload)
    if not isinstance(data, list):
        raise ValueError(f"Unexpected payload for {url}: {type(data)!r}")
    return data


def strip_html(raw: str | None) -> str:
    if not raw:
        return ""
    text = html.unescape(raw)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</?(strong|b)>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = text.replace("\r", "\n")
    lines = [re.sub(r"\s+", " ", part).strip(" .") for part in text.split("\n")]
    lines = [line for line in lines if line]
    return "\n".join(lines)


def normalize_address(raw: str) -> str:
    value = strip_html(raw)
    value = re.sub(r"\s+,", ",", value)
    value = re.sub(r"\s+\.", ".", value)
    return value.strip()


def normalize_phone(raw: str | None) -> str:
    value = strip_html(raw)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def build_records(location_type: str, city: str, payload: list[dict], fetched_at: str) -> list[LocationRecord]:
    source_page = f"{BASE_URL}/{'atms' if location_type == 'atm' else 'offices'}"
    records: list[LocationRecord] = []
    for item in payload:
        records.append(
            LocationRecord(
                location_type=location_type,
                city=city,
                address=normalize_address(str(item.get("address", ""))),
                latitude=float(item["lat"]),
                longitude=float(item["lon"]),
                hours=strip_html(str(item.get("graf_rab", ""))),
                phone=normalize_phone(item.get("phone")),
                source_url=source_page,
                fetched_at=fetched_at,
            )
        )
    return records


def fetch_all() -> list[LocationRecord]:
    fetched_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    all_records: list[LocationRecord] = []
    for city in CITIES:
        all_records.extend(build_records("atm", city, fetch_json("searchcity/json", city), fetched_at))
        all_records.extend(build_records("office", city, fetch_json("searchoffices/json", city), fetched_at))
    return all_records


def records_to_json(records: Iterable[LocationRecord]) -> str:
    items = [asdict(record) for record in records]
    return json.dumps(items, ensure_ascii=False, indent=2) + "\n"


def records_to_csv_text(records: Iterable[LocationRecord]) -> str:
    headers = [
        "location_type",
        "city",
        "address",
        "latitude",
        "longitude",
        "hours",
        "phone",
        "source_url",
        "fetched_at",
    ]
    from io import StringIO

    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=headers)
    writer.writeheader()
    for record in records:
        writer.writerow(asdict(record))
    return buffer.getvalue()


def records_to_xml(records: Iterable[LocationRecord]) -> str:
    root = ET.Element("locations", attrib={"bank": "Северный Народный Банк", "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat()})
    for record in records:
        item = ET.SubElement(root, "location")
        for key, value in asdict(record).items():
            node = ET.SubElement(item, key)
            node.text = str(value)
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode") + "\n"


def write_outputs(records: list[LocationRecord], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "sevnb_locations.json").write_text(records_to_json(records), encoding="utf-8")
    (output_dir / "sevnb_locations.csv").write_text(records_to_csv_text(records), encoding="utf-8")
    (output_dir / "sevnb_locations.xml").write_text(records_to_xml(records), encoding="utf-8")

    summary = {
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "bank": "Северный Народный Банк",
        "source": BASE_URL,
        "counts": {
            "total": len(records),
            "atms": sum(1 for record in records if record.location_type == "atm"),
            "offices": sum(1 for record in records if record.location_type == "office"),
        },
        "cities": sorted({record.city for record in records}),
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Build SNB ATM and office feed from sevnb.ru")
    parser.add_argument("--output-dir", default="dist", help="Directory for generated feed files")
    parser.add_argument("--stdout", choices=["json", "csv", "xml"], help="Print feed to stdout instead of only writing files")
    args = parser.parse_args(argv)

    records = fetch_all()
    write_outputs(records, Path(args.output_dir))

    if args.stdout == "json":
        sys.stdout.write(records_to_json(records))
    elif args.stdout == "csv":
        sys.stdout.write(records_to_csv_text(records))
    elif args.stdout == "xml":
        sys.stdout.write(records_to_xml(records))

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
