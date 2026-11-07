Device diagnostics, detailed history and compact device selection.

- Select a device to inspect DNS replies, reply-data status, observed routes and byte counters.
- Filter suspicious observations or browse all records; search by domain or IP.
- Keep diagnostic records in RAM for up to two hours, bounded to 1500 records across the network.
- Show dates in events and add device detail views, grouping and journal filters.
- Shorten device dropdown labels; show accumulated IPv6 addresses separately.
- Keep Russian and English UI, opt-in collection and authenticated read-only RPC.

No reply data is a suspicion, not proof of blocking. HTTPS contents, full URLs and HTTP status codes are not collected. DNS/Tachyon/connection detail integrations remain disabled by default.

Back up before upgrading. Stop Observatory, run the installer, restart rpcd, then start the collector. Restarting rpcd may require signing back into LuCI. Existing configuration is preserved.

---

Диагностика устройств, подробная история и компактный список устройств.

- DNS-ответы, соединения без ответных данных, наблюдаемые маршруты и счётчики передачи.
- Фильтры и поиск по домену/IP; до двух часов / 1500 записей в RAM.
- Даты в событиях, подробности устройства, группировка и фильтры журнала.
- Один IP в списке выбора; накопленные IPv6-адреса показаны отдельно.
- Русский и английский интерфейс; подробный сбор включается только явно.

Подозрение на отсутствие ответа не означает доказанную блокировку. Перед обновлением сохраните копию. Установщик не запускает сбор автоматически и сохраняет существующую конфигурацию.
