use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

/// Line-by-line iterator over a wordlist file or stdin.
/// Blank lines are skipped; trailing CR/LF is stripped.
pub struct LineIter {
    inner: Box<dyn BufRead + Send>,
    buf: String,
    pub line_no: u64,
}

impl LineIter {
    pub fn from_file(path: &Path) -> io::Result<Self> {
        let f = File::open(path)?;
        Ok(Self {
            inner: Box::new(BufReader::new(f)),
            buf: String::new(),
            line_no: 0,
        })
    }

    pub fn from_stdin() -> Self {
        Self {
            inner: Box::new(BufReader::new(io::stdin())),
            buf: String::new(),
            line_no: 0,
        }
    }

    /// Consume and discard the first `n` lines, advancing `line_no`.
    pub fn skip_lines(mut self, n: u64) -> Self {
        for _ in 0..n {
            self.buf.clear();
            match self.inner.read_line(&mut self.buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => self.line_no += 1,
            }
        }
        self
    }
}

impl Iterator for LineIter {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.buf.clear();
            match self.inner.read_line(&mut self.buf) {
                Ok(0) | Err(_) => return None,
                Ok(_) => {
                    self.line_no += 1;
                    let s = self.buf.trim_end_matches(['\n', '\r']).to_string();
                    if !s.is_empty() {
                        return Some(s);
                    }
                }
            }
        }
    }
}

/// Count newlines in a file (for progress ETA). Fast: reads in 64 KB chunks.
/// Off by at most 1 for files without a trailing newline, which is fine for progress.
pub fn count_lines(path: &Path) -> io::Result<u64> {
    let mut f = File::open(path)?;
    let mut buf = vec![0u8; 65536];
    let mut count = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        count += buf[..n].iter().filter(|&&b| b == b'\n').count() as u64;
    }
    Ok(count)
}
