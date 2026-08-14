# Один процесс Xray и одно gRPC-соединение для строгого аудита пользователей

## Задача

Строгий аудит VPnBot доказывает не только содержимое управляемого JSON-файла,
но и фактический реестр пользователей в уже работающем процессе Xray. Сейчас
узловой помощник запускает отдельную команду `xray api` для полного списка
inbound, затем отдельные команды списка и количества пользователей для каждого
inbound и повторяет весь проход второй раз. На узле с двенадцатью пользовательскими
inbound один строгий аудит создаёт примерно пятьдесят процессов Xray CLI и столько
же локальных gRPC-подключений; создание выполняет аудит до и после мутации.

Доказательная семантика правильна и не меняется. Ускорение должно убрать только
повторный запуск процесса и подключения:

```text
один vpnbot-xrayctl strict audit
  -> один xray api vpnbot-audit-users
  -> одно локальное gRPC-соединение
  -> pass 1: ListInbounds + GetInboundUsers + GetInboundUsersCount
  -> pass 2: ListInbounds + GetInboundUsers + GetInboundUsersCount
  -> один типизированный JSON-ответ
  -> прежнее сравнение managed/live и прежние digests в vpnbot-xrayctl
```

## Инварианты

- Полнота каждого `GetInboundUsers` по-прежнему независимо проверяется
  `GetInboundUsersCount`.
- Полный набор inbound и пользователей по-прежнему читается дважды. Любой drift
  между проходами даёт безопасную ошибку, а не частичный успех.
- Managed JSON, persisted confdir, systemd MainPID, process start time,
  `/proc/<pid>/exe`, API-listener inode и capability активного отзыва остаются
  прежними внешними доказательствами узлового помощника.
- Команда не пишет конфигурацию, не вызывает `AddUser`/`RemoveUser`, не
  перезапускает Xray и не хранит результат на диске.
- Пользовательские email и идентификаторы передаются только по локальному stdout
  между root-owned процессами. Они не попадают в журнал, manifest, pilot proof
  или операторский отчёт.
- Новый marker `vpnbot-live-user-audit-v1` относится только к оптимизированной
  CLI-команде. Существующий `vpnbot-active-revoke-v3` остаётся обязательным
  security-capability и не ослабляется.
- Узел без нового marker использует прежний строгий много-процессный путь. Узел,
  который marker заявил, но вернул некорректный ответ или сломанную команду,
  fail-closed завершает аудит ошибкой и не маскирует дефект fallback-ом.

## Формат ответа команды

Команда возвращает JSON-контракт `vpnbot-live-user-audit-v1` с двумя полными
проходами. Каждый проход содержит упорядоченный список inbound. Для каждого
inbound возвращаются tag, признак `UserManager`, полный protobuf-пользователь и
независимый count. Непользовательский inbound является нормальной строкой с
`user_manager=false`; любая иная RPC-ошибка завершает процесс ненулевым кодом.

`vpnbot-xrayctl` проверяет типы, точное число проходов, уникальность tag,
равенство count длине users и полное равенство двух снимков. Затем существующий
Python-код строит те же exact identities, runtime-only inbound id, managed/live
union и digests, что и до оптимизации. Контракт результата строгого аудита
остаётся `vpnbot-live-user-registry-v2`.

## Проверка и выпуск

1. Расширить третий существующий патч, сохранив ровно три файла в
   `patches/series`.
2. Добавить Go unit-тест команды и включить пакет `main/commands/all/api` в
   `scripts/test-patches.sh`.
3. Проверять оба capability-маркера в собранных amd64-бинарниках.
4. Расширить production-canary: до и после exact `RemoveUser` выполнить новую
   команду, доказать два прохода и точный состав пользователей, не записывая
   их в pilot proof.
5. Опубликовать candidate, дождаться CI, production-canary и byte-identical
   proven.
6. Сначала обновить Xray на canary/парке и развернуть helper с capability-gated
   fallback. Только затем выпускать центральный VPnBot-снимок.
7. На representative nodes сравнить старый и новый strict result по безопасным
   counts/digests, измерить wall time и число `xray api` процессов. Финальный
   аудит и node-wide mutating lock не удаляются.
