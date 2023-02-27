# Sqlite Database for ForensicRS
Sqlite implementation of SqlDb trait of ForensicRS

```rust
let mut fs = forensic_rs::core::fs::StdVirtualFS::new();
let file = fs.open(&temp_path).unwrap();
let w_conn = SqliteDB::virtual_file(file).unwrap();
let mut statement = w_conn.prepare("SELECT name, age FROM users;").unwrap();
test_database_content(statement.as_mut()).expect("Should not return error");
```