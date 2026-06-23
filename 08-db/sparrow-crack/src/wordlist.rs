use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

/// Line-by-line iterator over a wordlist file or stdin.
/// Blank lines are skipped; trailing CR/LF is stripped.
/// Lines with non-UTF-8 bytes are decoded lossily (replacement char) so the
/// iterator never aborts on Latin-1 or other 8-bit encodings in the wordlist.
pub struct LineIter {
    inner: Box<dyn BufRead + Send>,
    raw: Vec<u8>,
    pub line_no: u64,
}

impl LineIter {
    pub fn from_file(path: &Path) -> io::Result<Self> {
        let f = File::open(path)?;
        Ok(Self {
            inner: Box::new(BufReader::new(f)),
            raw: Vec::new(),
            line_no: 0,
        })
    }

    pub fn from_stdin() -> Self {
        Self {
            inner: Box::new(BufReader::new(io::stdin())),
            raw: Vec::new(),
            line_no: 0,
        }
    }

    /// Read one raw line; returns false on EOF.
    fn read_raw_line(&mut self) -> bool {
        self.raw.clear();
        matches!(self.inner.read_until(b'\n', &mut self.raw), Ok(n) if n > 0)
    }

    /// Decode the current raw line, stripping CR/LF.
    fn current_line(&self) -> String {
        let trimmed = self.raw.iter().rposition(|&b| b != b'\n' && b != b'\r')
            .map_or(&[][..], |i| &self.raw[..=i]);
        String::from_utf8_lossy(trimmed).into_owned()
    }

    /// Consume and discard the first `n` non-blank lines, advancing `line_no`.
    pub fn skip_lines(mut self, n: u64) -> Self {
        let mut skipped = 0u64;
        while skipped < n {
            if !self.read_raw_line() { break; }
            self.line_no += 1;
            if !self.current_line().is_empty() {
                skipped += 1;
            }
        }
        self
    }
}

impl Iterator for LineIter {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if !self.read_raw_line() { return None; }
            self.line_no += 1;
            let s = self.current_line();
            if !s.is_empty() {
                return Some(s);
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
