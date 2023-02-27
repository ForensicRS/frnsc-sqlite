use std::{io::Write, time::{UNIX_EPOCH, SystemTime, Duration}};

use forensic_rs::{
    prelude::{ForensicError, ForensicResult},
    traits::{sql::{ColumnType, ColumnValue, SqlDb, SqlStatement}, vfs::VirtualFile},
};
use sqlite::{Connection, Statement, OpenFlags};

/// SQLite DB that implements the forensic SqlDb trait
pub struct SqliteDB {
    conn: Connection,
}

impl SqliteDB {
    pub fn new(conn: Connection) -> SqliteDB {
        SqliteDB { conn }
    }
    /// Create an empty in-memmory DB
    pub fn empty() -> SqliteDB {
        SqliteDB { conn: sqlite::open(":memory:").unwrap() }
    }
    /// Create a SQLite DB from a virtual file in ReadOnly and Serialized mode. The implementation copies the entire SQLite into a temp folder and opens it.
    /// The alternative is create a custom VFS for SQLite. https://www.sqlite.org/vfs.html
    pub fn virtual_file(mut file: Box<dyn VirtualFile>) -> ForensicResult<SqliteDB> {
        // We need to copy the full file from the virtual filesystem into a temp file in the machine
        let mut buffer = vec![0; 4096];
        let millis = match SystemTime::now()
            .duration_since(UNIX_EPOCH) {
                Ok(v) => v,
                Err(_) => Duration::from_secs(1)
            }.subsec_nanos();
        let file_name =format!("forensic_sqlite.{}.db", millis);
        let temp_path = std::env::temp_dir().join(file_name);
        let mut tmp_file = std::fs::File::create(&temp_path)?;
        loop {
            let readed = file.read(&mut buffer)?;
            if readed == 0 {
                break;
            }
            tmp_file.write_all(&buffer[0..readed])?;
        }
        let connection = match sqlite::Connection::open_with_flags(&temp_path.to_string_lossy()[..], OpenFlags::new().set_read_only().set_full_mutex()) {
            Ok(v) => v,
            Err(e) => return Err(ForensicError::Other(e.to_string()))
        };
        Ok(SqliteDB::new(connection))
    }
}

impl SqlDb for SqliteDB {
    fn prepare<'a>(&'a self, statement: &'a str) -> ForensicResult<Box<dyn SqlStatement + 'a>> {
        Ok(Box::new(SqliteStatement::new(&self.conn, statement)?))
    }

    fn from_file(&self, file: Box<dyn VirtualFile>) -> ForensicResult<Box<dyn SqlDb>> {
        Ok(Box::new(Self::virtual_file(file)?))
    }
    fn list_tables(&self) -> ForensicResult<Vec<String>> {
        let mut ret = Vec::with_capacity(32);
        let mut sts = self.prepare(r#"SELECT 
        name
    FROM 
        sqlite_schema
    WHERE 
        type ='table' AND 
        name NOT LIKE 'sqlite_%';"#)?;
        loop {
            if !sts.next()? {
                break;
            }
            let name : String = sts.read(0)?.try_into()?;
            ret.push(name);
        }
        Ok(ret)
    }
}

pub struct SqliteStatement<'conn> {
    stmt: Statement<'conn>,
}
impl<'conn> SqliteStatement<'conn> {
    pub fn new(conn: &'conn Connection, statement: &str) -> ForensicResult<SqliteStatement<'conn>> {
        Ok(Self {
            stmt: match conn.prepare(statement) {
                Ok(st) => st,
                Err(e) => return Err(ForensicError::Other(e.to_string())),
            },
        })
    }
}

impl<'conn> SqlStatement for SqliteStatement<'conn> {
    fn column_count(&self) -> usize {
        self.stmt.column_count()
    }

    fn column_name(&self, i: usize) -> Option<&str> {
        match self.stmt.column_name(i) {
            Ok(v) => Some(v),
            Err(_) => None,
        }
    }

    fn column_names(&self) -> Vec<&str> {
        self.stmt.column_names().iter().map(|v| &v[..]).collect()
    }

    fn column_type(&self, i: usize) -> ColumnType {
        let column_type = match self.stmt.column_type(i) {
            Ok(v) => v,
            Err(_e) => return ColumnType::Null,
        };
        match column_type {
            sqlite::Type::Binary => ColumnType::Binary,
            sqlite::Type::Float => ColumnType::Float,
            sqlite::Type::Integer => ColumnType::Integer,
            sqlite::Type::String => ColumnType::String,
            sqlite::Type::Null => ColumnType::Null,
        }
    }

    fn next(&mut self) -> ForensicResult<bool> {
        match self.stmt.next() {
            Ok(v) => Ok(match v {
                sqlite::State::Row => true,
                sqlite::State::Done => false,
            }),
            Err(e) => Err(ForensicError::Other(e.to_string())),
        }
    }

    fn read(&self, i: usize) -> ForensicResult<ColumnValue> {
        let column_type = match self.stmt.column_type(i) {
            Ok(v) => v,
            Err(e) => return Err(ForensicError::Other(e.to_string())),
        };
        match column_type {
            sqlite::Type::Binary => match self.stmt.read(i) {
                Ok(v) => Ok(ColumnValue::Binary(v)),
                Err(e) => Err(ForensicError::Other(e.to_string())),
            },
            sqlite::Type::Float => match self.stmt.read(i) {
                Ok(v) => Ok(ColumnValue::Float(v)),
                Err(e) => Err(ForensicError::Other(e.to_string())),
            },
            sqlite::Type::Integer => match self.stmt.read(i) {
                Ok(v) => Ok(ColumnValue::Integer(v)),
                Err(e) => Err(ForensicError::Other(e.to_string())),
            },
            sqlite::Type::String => match self.stmt.read(i) {
                Ok(v) => Ok(ColumnValue::String(v)),
                Err(e) => Err(ForensicError::Other(e.to_string())),
            },
            sqlite::Type::Null => Ok(ColumnValue::Null),
        }
    }
}

#[cfg(test)]
mod test_db_implementation {
    use super::*;

    use forensic_rs::{traits::{sql::{SqlStatement, SqlDb}, vfs::VirtualFileSystem}, prelude::ForensicResult};
    use sqlite::Connection;

    use crate::SqliteDB;

    fn initialize_mem_db() -> Connection {
        let connection = sqlite::open(":memory:").unwrap();
        prepare_db(connection)
    }
    fn initialize_file_db() -> Connection {
        let millis = match SystemTime::now()
            .duration_since(UNIX_EPOCH) {
                Ok(v) => v,
                Err(_) => Duration::from_secs(1)
            }.subsec_nanos();
        let file_name =format!("forensic_sqlite.{}.db", millis);
        let temp_path = std::env::temp_dir().join(file_name);
        let connection = sqlite::open(&temp_path).unwrap();
        prepare_db(connection)
    }

    fn prepare_db(connection : Connection) -> Connection {
        connection
            .execute(
                "
            CREATE TABLE users (name TEXT, age INTEGER);
            INSERT INTO users VALUES ('Alice', 42);
            INSERT INTO users VALUES ('Bob', 69);
            ",
            )
            .unwrap();
        connection
    }
    fn prepare_wrapper(connection: Connection) -> SqliteDB {
        SqliteDB::new(connection)
    }

    #[test]
    fn sqlite_in_memory() {
        let conn = initialize_mem_db();
        let w_conn = prepare_wrapper(conn);
        let mut statement = w_conn.prepare("SELECT name, age FROM users;").unwrap();
        test_database_content(statement.as_mut()).expect("Should not return error");
    }

    #[test]
    fn sqlite_from_machine_file() {
        let conn = initialize_file_db();
        let w_conn = prepare_wrapper(conn);
        let mut statement = w_conn.prepare("SELECT name, age FROM users;").unwrap();
        test_database_content(statement.as_mut()).expect("Should not return error");
    }

    #[test]
    fn sqlite_from_virtual_file() {
        let millis = match SystemTime::now()
            .duration_since(UNIX_EPOCH) {
                Ok(v) => v,
                Err(_) => Duration::from_secs(1)
            }.as_millis();
        let file_name =format!("forensic_sqlite.{}.db", millis);
        let temp_path = std::env::temp_dir().join(file_name);
        let connection = sqlite::open(&temp_path).unwrap();
        prepare_db(connection);

        let mut fs = forensic_rs::core::fs::StdVirtualFS::new();
        let file = fs.open(&temp_path).unwrap();
        let w_conn = SqliteDB::virtual_file(file).unwrap();
        let mut statement = w_conn.prepare("SELECT name, age FROM users;").unwrap();
        test_database_content(statement.as_mut()).expect("Should not return error");
    }

    fn test_database_content<'a>(statement: &mut dyn SqlStatement) -> ForensicResult<()> {
        assert!(statement.next()?);
        let name: String = statement.read(0)?.try_into()?;
        let age: usize = statement.read(1)?.try_into()?;
        assert_eq!("Alice", name);
        assert_eq!(42, age);
        assert!(statement.next()?);
        let name: String = statement.read(0)?.try_into()?;
        let age: usize = statement.read(1)?.try_into()?;
        assert_eq!("Bob", name);
        assert_eq!(69, age);
        assert!(!statement.next()?);
        Ok(())
    }
}
