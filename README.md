# VisualPetri MCP

Локальный MCP-сервер для выполнения лабораторной работы по сетям Петри: построение сценариев атак, анализ достижимости, формирование матрицы инцидентности, экспорт схем и подготовка материалов для отчёта.

Сервер работает через `stdio`, поэтому его можно подключить к Codex, Claude Code, Claude Desktop, Cursor и VS Code. Для построения красивых схем VisualPetri не обязателен: встроенный рендерер создаёт PNG и SVG самостоятельно. На Windows можно дополнительно подключить `VisualPetri.exe` для автоматизации исходной учебной программы.

## Возможности

- создание и проверка моделей сетей Петри из JSON;
- поддержка обычных, ингибиторных, информационных дуг и сброса;
- пошаговый запуск переходов и поиск графа достижимости;
- автоматический анализ тупиков, недостижимых мест и переходов;
- построение матрицы инцидентности `C = Post - Pre`;
- экспорт основной схемы, графа достижимости и дерева атаки в PNG/SVG;
- генерация Markdown-отчёта с таблицами и готовыми иллюстрациями;
- импорт и экспорт файлов VisualPetri `.spped`;
- экспериментальная автоматизация VisualPetri GUI на Windows.

## Соответствие заданию

| Требование лабораторной | Инструменты MCP |
|---|---|
| Модель злоумышленника и цели атаки | `create_attack_model`, `load_model` |
| Вектор атаки и последовательность действий | `create_attack_model`, `simulate_sequence` |
| Сеть Петри и правила срабатывания | `validate_model`, `enabled_transitions`, `fire_transition` |
| Граф достижимости | `analyze_reachability`, `render_reachability_graph` |
| Матрица инцидентности | `incidence_matrix` |
| Поиск тупиков и недостижимых элементов | `analyze_reachability` |
| Дерево атаки | `render_attack_tree` |
| Скриншоты для отчёта | `render_petri_net`, `render_reachability_graph`, `render_attack_tree` |
| Итоговый отчёт | `generate_report` |
| Работа с VisualPetri | `export_visualpetri`, `import_visualpetri`, `visualpetri_gui` |

## Установка

Нужны Git и Python 3.10 или новее.

Репозиторий приватный. Чтобы дать другу доступ, откройте на GitHub **Settings → Collaborators → Add people** и укажите его GitHub-логин. После принятия приглашения он сможет выполнить обычный `git clone` по инструкции ниже. Если сделать репозиторий публичным в **Settings → General → Change repository visibility**, приглашения не понадобятся.

### macOS и Linux

```bash
git clone https://github.com/everlnggg/visualpetri-mcp.git
cd visualpetri-mcp
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
chmod +x run_server.sh
```

### Windows PowerShell

```powershell
git clone https://github.com/everlnggg/visualpetri-mcp.git
cd visualpetri-mcp
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
```

## Подключение к клиентам

В командах ниже рабочие файлы будут сохраняться в папку `workspace` внутри репозитория.

### Codex CLI и Codex Desktop

macOS/Linux:

```bash
codex mcp add visualpetri \
  --env PETRI_MCP_HOME="$PWD/workspace" \
  -- "$PWD/.venv/bin/python" -m petri_mcp.server
codex mcp list
```

Windows PowerShell:

```powershell
codex mcp add visualpetri --env "PETRI_MCP_HOME=$PWD\workspace" -- "$PWD\.venv\Scripts\python.exe" -m petri_mcp.server
codex mcp list
```

После добавления перезапустите клиент Codex, если сервер не появился сразу.

### Claude Code

macOS/Linux:

```bash
claude mcp add visualpetri --scope user \
  --env PETRI_MCP_HOME="$PWD/workspace" \
  -- "$PWD/.venv/bin/python" -m petri_mcp.server
claude mcp list
```

Windows PowerShell:

```powershell
claude mcp add visualpetri --scope user --env "PETRI_MCP_HOME=$PWD\workspace" -- "$PWD\.venv\Scripts\python.exe" -m petri_mcp.server
claude mcp list
```

В интерактивном сеансе Claude Code состояние подключения также видно через `/mcp`.

### Claude Desktop

Откройте конфигурацию:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Добавьте сервер, заменив абсолютные пути:

```json
{
  "mcpServers": {
    "visualpetri": {
      "command": "/ABSOLUTE/PATH/visualpetri-mcp/.venv/bin/python",
      "args": ["-m", "petri_mcp.server"],
      "env": {
        "PETRI_MCP_HOME": "/ABSOLUTE/PATH/visualpetri-mcp/workspace"
      }
    }
  }
}
```

Готовый шаблон: [`config/claude-desktop.json.example`](config/claude-desktop.json.example).

### Cursor

Создайте `.cursor/mcp.json` в своём проекте и скопируйте туда содержимое [`config/cursor.mcp.json.example`](config/cursor.mcp.json.example), заменив абсолютные пути. Затем перезапустите Cursor или включите сервер в **Settings → Tools & MCP**.

### VS Code

Создайте `.vscode/mcp.json` и скопируйте туда [`config/vscode.mcp.json.example`](config/vscode.mcp.json.example), заменив абсолютные пути. Запуск и проверка сервера доступны через команду **MCP: List Servers**.

## Подключение VisualPetri на Windows

VisualPetri нужен только для GUI-автоматизации и создания `.spped` в оригинальной программе. Укажите путь к локальному EXE:

```powershell
$env:VISUALPETRI_EXE = "C:\Path\To\VisualPetri.exe"
```

Не добавляйте `VisualPetri.exe` и учебную методичку в репозиторий: у этих файлов может быть отдельная лицензия.

## Быстрый запрос агенту

После подключения MCP можно написать:

> Создай в VisualPetri MCP модель инсайдерской атаки на базу данных. Проверь модель, построй граф достижимости, матрицу инцидентности и дерево атаки. Экспортируй PNG/SVG и собери Markdown-отчёт. Покажи абсолютные пути ко всем результатам.

Либо передать готовую модель:

```text
Загрузи examples/insider_attack.json через load_model, выполни analyze_reachability,
render_petri_net, render_reachability_graph, render_attack_tree и generate_report.
```

## Основные инструменты MCP

| Инструмент | Назначение |
|---|---|
| `create_attack_model` | создаёт модель атаки из структурированного описания |
| `load_model` / `save_model` | читает и сохраняет JSON-модель |
| `validate_model` | проверяет корректность мест, переходов, дуг и маркировки |
| `enabled_transitions` | показывает разрешённые переходы |
| `fire_transition` | выполняет один переход |
| `simulate_sequence` | проигрывает последовательность переходов |
| `analyze_reachability` | строит ограниченный граф достижимости и диагностику |
| `incidence_matrix` | вычисляет матрицы `Pre`, `Post` и `C` |
| `render_petri_net` | экспортирует схему сети в PNG/SVG |
| `render_reachability_graph` | экспортирует граф достижимости |
| `render_attack_tree` | экспортирует дерево атаки |
| `generate_report` | создаёт Markdown-отчёт и все иллюстрации |
| `export_visualpetri` / `import_visualpetri` | работает с форматом `.spped` |
| `visualpetri_gui` | запускает сценарии автоматизации Windows GUI |

## Локальная демонстрация без MCP-клиента

```bash
.venv/bin/python -m petri_mcp.cli --root workspace create examples/insider_attack.json
.venv/bin/python -m petri_mcp.cli --root workspace export insider_attack_demo output/demo
```

На Windows:

```powershell
.\.venv\Scripts\python.exe -m petri_mcp.cli --root workspace create examples\insider_attack.json
.\.venv\Scripts\python.exe -m petri_mcp.cli --root workspace export insider_attack_demo output\demo
```

## Тесты

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Тесты также запускаются в GitHub Actions на Python 3.10–3.13.

## Ограничения

- Анализ достижимости ограничивается параметрами `max_states` и `max_depth`, чтобы не зависнуть на неограниченной сети.
- GUI-автоматизация VisualPetri рассчитана на Windows и требует установленного `pywinauto` (`pip install -e '.[windows]'`).
- Встроенный рендерер создаёт отчётные иллюстрации независимо от VisualPetri и подходит для macOS, Linux и Windows.

## Документация клиентов

- [Codex: подключение MCP-серверов](https://developers.openai.com/learn/docs-mcp)
- [Claude Code: MCP](https://code.claude.com/docs/en/mcp)
- [MCP Python SDK: запуск в реальном клиенте](https://py.sdk.modelcontextprotocol.io/get-started/real-host/)

## Лицензирование исходных материалов

Репозиторий содержит только MCP-сервер и демонстрационный JSON. Методичка, учебные материалы и бинарные файлы VisualPetri не публикуются.
