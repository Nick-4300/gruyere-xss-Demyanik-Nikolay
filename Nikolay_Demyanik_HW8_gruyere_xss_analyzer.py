#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Анализ HTTP-трафика Google Gruyere с помощью Scapy.
Поддерживает:
  - живой перехват (live capture)
  - чтение сохранённого .pcap
  - автоматическую декомпрессию gzip (через TCPSession)
  - поиск XSS-полезной нагрузки
"""

import argparse
import sys
import gzip
import io
from datetime import datetime

from scapy.all import (
    sniff, IP, TCP, Raw, conf,
    PcapWriter, rdpcap, load_layer
)
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse, TCPSession

# Явно загружаем HTTP-слой (он не загружается по умолчанию)
load_layer("http")

# Включаем автоматическую декомпрессию и сборку чанков (по умолчанию True)
conf.contribs["http"]["auto_compression"] = True
conf.contribs["http"]["auto_chunk"] = True


def safe_decode(data: bytes, encoding: str = "utf-8") -> str:
    """Безопасное декодирование байтов в строку."""
    if isinstance(data, str):
        return data
    try:
        return data.decode(encoding, errors="replace")
    except Exception:
        return repr(data)


def decompress_body(body: bytes, headers: dict) -> bytes:
    """
    Ручная распаковка gzip/deflate, если автоматическая не сработала.
    headers — словарь с ключами в нижнем регистре.
    """
    if not body:
        return body
    content_encoding = headers.get("content-encoding", "").lower()
    if "gzip" in content_encoding:
        try:
            return gzip.decompress(body)
        except Exception:
            pass
    # deflate можно попробовать через zlib, но обычно TCPSession справляется сам
    return body


def format_http_message(pkt, is_request: bool) -> str:
    """Формирует читаемое представление HTTP-запроса или ответа."""
    lines = []
    if is_request and HTTPRequest in pkt:
        req = pkt[HTTPRequest]
        method = safe_decode(req.Method)
        path = safe_decode(req.Path)
        version = safe_decode(req.Http_Version)
        lines.append(f"{method} {path} {version}")

        # Заголовки
        for field in req.fields_desc:
            name = field.name
            if name in ("Method", "Path", "Http_Version"):
                continue
            val = req.getfieldval(name)
            if val is not None:
                lines.append(f"{name.replace('_', '-')}: {safe_decode(val)}")

        # Тело
        if Raw in pkt:
            body = pkt[Raw].load
            body = decompress_body(body, {})  # заголовки пока не передаём
            lines.append("\n--- BODY ---")
            lines.append(safe_decode(body))

    elif not is_request and HTTPResponse in pkt:
        resp = pkt[HTTPResponse]
        status_line = f"{safe_decode(resp.Http_Version)} {resp.Status_Code} {safe_decode(resp.Reason_Phrase)}"
        lines.append(status_line)

        headers = {}
        for field in resp.fields_desc:
            name = field.name
            if name in ("Http_Version", "Status_Code", "Reason_Phrase"):
                continue
            val = resp.getfieldval(name)
            if val is not None:
                header_name = name.replace("_", "-")
                header_val = safe_decode(val)
                headers[header_name.lower()] = header_val
                lines.append(f"{header_name}: {header_val}")

        # Тело (с ручной распаковкой на всякий случай)
        if Raw in pkt:
            body = pkt[Raw].load
            body = decompress_body(body, headers)
            lines.append("\n--- BODY ---")
            lines.append(safe_decode(body))

    return "\n".join(lines)


def packet_callback(pkt, search_payload: str = None, show_body: bool = True):
    """Обработчик каждого собранного HTTP-сообщения (после сборки TCPSession)."""
    if HTTPRequest in pkt:
        print("\n" + "=" * 80)
        print(f"[HTTP REQUEST] {pkt[IP].src} -> {pkt[IP].dst}:{pkt[TCP].dport}")
        print("=" * 80)
        msg = format_http_message(pkt, is_request=True)
        print(msg)

        if search_payload and search_payload.lower() in msg.lower():
            print("\n🔍 *** НАЙДЕНА XSS-ПОЛЕЗНАЯ НАГРУЗКА В ЗАПРОСЕ! ***")

    elif HTTPResponse in pkt:
        print("\n" + "-" * 80)
        print(f"[HTTP RESPONSE] {pkt[IP].src} -> {pkt[IP].dst}:{pkt[TCP].sport}")
        print("-" * 80)
        msg = format_http_message(pkt, is_request=False)
        print(msg)

        if search_payload and search_payload.lower() in msg.lower():
            print("\n🔍 *** НАЙДЕНА XSS-ПОЛЕЗНАЯ НАГРУЗКА В ОТВЕТЕ! ***")


def live_capture(iface: str = None, pcap_out: str = None,
                 search_payload: str = None, count: int = 0):
    """Живой перехват HTTP-трафика с сохранением в pcap."""
    writer = None
    if pcap_out:
        writer = PcapWriter(pcap_out, append=True, sync=True)
        print(f"[*] Сохранение трафика в файл: {pcap_out}")

    print("[*] Начат перехват HTTP-трафика (Ctrl+C для остановки)...")
    try:
        sniff(
            iface=iface,
            filter="tcp port 80",   # Gruyere работает по HTTP (порт 80)
            prn=lambda pkt: (
                writer.write(pkt) if writer else None,
                packet_callback(pkt, search_payload)
            ),
            session=TCPSession,       # сборка TCP-потоков + декомпрессия
            store=False,
            count=count if count > 0 else 0
        )
    except KeyboardInterrupt:
        print("\n[*] Перехват остановлен пользователем.")
    finally:
        if writer:
            writer.close()
            print(f"[*] Трафик сохранён: {pcap_out}")


def analyze_pcap(pcap_file: str, search_payload: str = None):
    """Анализ сохранённого .pcap-файла."""
    print(f"[*] Чтение pcap: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"[*] Всего пакетов: {len(packets)}")

    # Для сборки HTTP-потоков из pcap используем TCPSession
    from scapy.all import AsyncSniffer
    # Простейший способ — повторно «прокрутить» пакеты через sniff(offline=...)
    # с TCPSession, но можно и вручную. Ниже — надёжный вариант:
    print("[*] Сборка HTTP-сообщений (TCPSession)...\n")
    sniff(offline=pcap_file, session=TCPSession,
          prn=lambda pkt: packet_callback(pkt, search_payload),
          store=False)


def main():
    parser = argparse.ArgumentParser(
        description="Scapy HTTP-анализатор для Google Gruyere (XSS lab)"
    )
    parser.add_argument("--iface", help="Сетевой интерфейс (например, eth0, wlan0)")
    parser.add_argument("--pcap-out", help="Файл для сохранения перехваченного трафика (.pcap)")
    parser.add_argument("--pcap-in", help="Анализировать существующий .pcap-файл")
    parser.add_argument("--search", help="Строка XSS-полезной нагрузки для поиска в трафике")
    parser.add_argument("--count", type=int, default=0,
                        help="Количество пакетов для захвата (0 = без ограничений)")

    args = parser.parse_args()

    if args.pcap_in:
        analyze_pcap(args.pcap_in, args.search)
    else:
        live_capture(args.iface, args.pcap_out, args.search, args.count)


if __name__ == "__main__":
    # Для захвата требуются права root/sudo
    if not sys.platform.startswith("win") and __import__("os").geteuid() != 0:
        print("[!] ВНИМАНИЕ: для перехвата трафика требуются права root (sudo).")
    main()