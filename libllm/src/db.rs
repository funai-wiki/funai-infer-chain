#![allow(dead_code)]

use std::error;

use rusqlite::Error::QueryReturnedNoRows;
use rusqlite::types::ToSql;
use rusqlite::{
    Connection, NO_PARAMS,
    params,
};

#[derive(Debug)]
pub struct ResultRow {
    pub txid: String,
    pub context: String,
    pub input: String,
    pub output: String,
    pub output_hash: String,
    pub status: u8,
    pub create_time: String,
    pub start_time: String,
    pub end_time: String
}

pub const LLM_DB_PATH: &str = "./llm.sqlite";

pub fn initialize_conn(conn: &Connection) -> Result<(), Box<dyn error::Error>> {
    conn.query_row("PRAGMA journal_mode = WAL;", NO_PARAMS, |_row| Ok(()))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS result_table
                  (txid TEXT PRIMARY KEY, context TEXT default '', input TEXT default '',
                   output TEXT default '', output_hash TEXT default '',
                   status INTEGER, create_time TEXT default '',
                   start_time TEXT default '', end_time TEXT default '')",
        NO_PARAMS,
    )?;

    let sql = "SELECT sql FROM sqlite_master WHERE name=?";
    let _: String = conn
        .query_row(sql, &["result_table"], |row| row.get(0))?;

    Ok(())
}

pub fn open(filename: &str) -> Result<Connection, Box<dyn error::Error>> {
    let llm_db = Connection::open(filename)?;
    initialize_conn(&llm_db)?;
    Ok(llm_db)
}

pub fn sqlite_create(conn: &Connection, txid: &str, context: &str, input: &str, status: u8) -> Result<(), Box<dyn error::Error>> {
    let params: [&dyn ToSql; 4] = [&txid, &context, &input, &status];
    conn.execute(
        "REPLACE INTO result_table (txid, context, input, status, create_time) VALUES (?, ?, ?, ?, datetime('now'))",
        &params,
    )?;
    Ok(())
}

pub fn sqlite_start_llm(conn: &Connection, txid: &str, status: u8) -> Result<(), Box<dyn error::Error>> {
    let params: [&dyn ToSql; 2] = [&txid, &status];
    conn.execute(
        "UPDATE result_table SET status = ?2, start_time = datetime('now') WHERE txid = ?1",
        &params,
    )?;
    Ok(())
}

pub fn sqlite_end_llm(conn: &Connection, txid: &str, output: &str, output_hash: &str, status: u8) -> Result<(), Box<dyn error::Error>> {
    let params: [&dyn ToSql; 4] = [&txid, &output, &output_hash, &status];
    conn.execute(
        "UPDATE result_table SET output = ?2, output_hash = ?3, status = ?4, end_time = datetime('now') WHERE txid = ?1",
        &params,
    )?;
    Ok(())
}

pub fn sqlite_get(conn: &Connection, txid: &str) -> Result<ResultRow, Box<dyn error::Error>> {
    let params: [&dyn ToSql; 1] = [&txid];
    let result = conn.query_row(
        "SELECT txid, context, input, output, output_hash, status, create_time, start_time, end_time FROM result_table WHERE txid = ?",
        &params,
        |row| {
            Ok( ResultRow {
                txid: row.get(0)?,
                context: row.get(1)?,
                input: row.get(2)?,
                output: row.get(3)?,
                output_hash: row.get(4)?,
                status: row.get(5)?,
                create_time: row.get(6)?,
                start_time: row.get(7)?,
                end_time: row.get(8)?,
            })
        }
    );
    match result {
        Ok(row) => Ok(row),
        Err(QueryReturnedNoRows) => Ok(ResultRow{
            txid: "".to_string(),
            context: "".to_string(),
            input: "".to_string(),
            output: "".to_string(),
            output_hash: "".to_string(),
            status: 5u8, // NotFound
            create_time: "".to_string(),
            start_time: "".to_string(),
            end_time: "".to_string(),
        }),
        Err(e) => Err(Box::new(e)),
    }
}

pub fn sqlite_filter_to_infer(conn: &Connection) -> Result<ResultRow, Box<dyn error::Error>> {
    let result = conn.query_row(
        "SELECT txid, context, input, output, output_hash, status, create_time, start_time, end_time FROM result_table WHERE status = ? OR status = ? ORDER BY create_time",
        params![1u32, 4u8],
        |row| {
            Ok( ResultRow {
                txid: row.get(0)?,
                context: row.get(1)?,
                input: row.get(2)?,
                output: row.get(3)?,
                output_hash: row.get(4)?,
                status: row.get(5)?,
                create_time: row.get(6)?,
                start_time: row.get(7)?,
                end_time: row.get(8)?,
            })
        }
    )?;
    Ok(result)
}