# chrome_history_sample fixture

`History` in this directory is a synthetic but structurally real SQLite
database (Chromium `History` schema: `urls` + `visits`, 800 rows each,
4096-byte pages, ~30 pages) generated with Python's stdlib `sqlite3` module
— not hand-built — so the test suite validates this crate's from-scratch
b-tree/overflow-page implementation against real SQLite output.

Row 501 has a deliberately oversized (6009-byte) title, forcing at least one
overflow-page chain.

Regenerate with:

```bash
python3 - <<'PYEOF'
import sqlite3, os, random, string

path = "History"
if os.path.exists(path):
    os.remove(path)

con = sqlite3.connect(path)
cur = con.cursor()
cur.execute("PRAGMA page_size=4096")
cur.execute("""CREATE TABLE urls(id INTEGER PRIMARY KEY,url LONGVARCHAR,title LONGVARCHAR,
    visit_count INTEGER DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,
    last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL)""")
cur.execute("""CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER NOT NULL,
    visit_time INTEGER NOT NULL,from_visit INTEGER,transition INTEGER DEFAULT 0 NOT NULL,
    segment_id INTEGER,visit_duration INTEGER DEFAULT 0 NOT NULL)""")

random.seed(42)
for i in range(800):
    url = f"https://example{i}.test/path/{i}?q={i}"
    if i == 500:
        title = "OVERFLOW-" + "".join(random.choices(string.ascii_letters, k=6000))
    else:
        title = f"Example Page {i} - " + "".join(random.choices(string.ascii_letters, k=20))
    visit_count = i % 37
    last_visit = 13350000000000000 + i * 1000000
    cur.execute("INSERT INTO urls(url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (?,?,?,?,?,0)",
                (url, title, visit_count, i % 5, last_visit))
    cur.execute("INSERT INTO visits(url, visit_time, from_visit, transition, segment_id, visit_duration) VALUES (?,?,?,?,?,?)",
                (i + 1, last_visit, None, 805306368, None, 1000 * i))

con.commit()
con.close()
PYEOF
```

A copy also lives at
`../pipeline_fixture/Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History`
for the glob-discovery/`TriagePipeline` tests in `src/artifacts/parser.rs` —
regenerate both together (`cp History "../pipeline_fixture/Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History"`).
